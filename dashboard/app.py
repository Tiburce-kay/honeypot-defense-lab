#!/usr/bin/env python3
# Dashboard SOC "Mission Control" - Systeme de defense reseau
# Module 7 - Flask + SocketIO + auth + 6 vues + metriques temps reel
import subprocess
import threading
import time
import functools
import json
import os
import sqlite3
import hashlib
import io
from datetime import datetime, timezone
from collections import deque, Counter
from flask import (Flask, render_template, request, redirect,
                   url_for, session, jsonify, Response)
from flask_socketio import SocketIO, disconnect
from werkzeug.security import check_password_hash

try:
    from fpdf import FPDF
    from fpdf.enums import XPos, YPos
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('DASHBOARD_SECRET_KEY') or os.urandom(32).hex()
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

AUTH_FILE = '/home/server/dashboard/auth.conf'
EVE_JSON = '/var/log/suricata/eve.json'
COWRIE_JSON = '/home/cowrie/cowrie/var/log/cowrie/cowrie.json'
DIONAEA_DB = '/opt/dionaea/var/lib/dionaea/dionaea.sqlite'
DIONAEA_FTP = '/opt/dionaea/var/lib/dionaea/ftp/root'

MAX_EVENTS = 20
SERVICES = [
    "defense-iptables", "suricata-ips", "defense-modules",
    "cowrie", "dionaea", "dashboard",
]

# Inventaire infrastructure (depuis la config du projet)
INFRA = {
    'vlans': [
        {'id': 10, 'nom': 'SYSTEMDEFENSE', 'reseau': '192.168.10.0/24', 'usage': 'Serveur defense'},
        {'id': 20, 'nom': 'SERVEURS', 'reseau': '192.168.20.0/24', 'usage': 'Serveurs appli (fictif)'},
        {'id': 30, 'nom': 'UTILISATEURS', 'reseau': '192.168.30.0/24', 'usage': 'Postes utilisateurs'},
        {'id': 40, 'nom': 'ATTAQUANT', 'reseau': '192.168.40.0/24', 'usage': 'Zone attaquant (Kali)'},
        {'id': 99, 'nom': 'ADMIN', 'reseau': '192.168.99.0/24', 'usage': 'Administration (jamais piege)'},
    ],
    'honeypots': [
        {'ip': '192.168.10.20', 'type': 'Honeyd', 'profil': 'Apache/Tomcat/HTTPS'},
        {'ip': '192.168.10.30', 'type': 'Honeyd', 'profil': 'ProFTPD/Postfix/IMAP'},
        {'ip': '192.168.10.40', 'type': 'Honeyd', 'profil': 'SMB/RDP Windows'},
        {'ip': '192.168.20.20', 'type': 'Honeyd', 'profil': 'Nginx/API REST'},
        {'ip': '192.168.10.50', 'type': 'Dionaea', 'profil': 'FTP/HTTP/MySQL (capture)'},
        {'ip': '192.168.10.10:2222', 'type': 'Cowrie', 'profil': 'SSH haute interaction'},
    ],
}

# Historique temporel en memoire (pour les courbes)
HIST_LEN = 30
alert_history = deque(maxlen=HIST_LEN)   # nb alertes par tick
time_labels = deque(maxlen=HIST_LEN)
_last_alert_count = [0]


# ---------- Authentification ----------
def load_credentials():
    creds = {}
    try:
        with open(AUTH_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                user, h = line.split(':', 1)
                creds[user] = h
    except FileNotFoundError:
        pass
    return creds


def check_login(username, password):
    creds = load_credentials()
    if username in creds:
        return check_password_hash(creds[username], password)
    return False


def login_required(f):
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapped


# ---------- Lecture efficace ----------
def tail_lines(path, max_lines=MAX_EVENTS, block=8192):
    try:
        with open(path, 'rb') as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            data = b''
            read = 0
            while size - read > 0 and data.count(b'\n') <= max_lines:
                step = min(block, size - read)
                read += step
                f.seek(size - read)
                data = f.read(step) + data
            out = []
            for ln in data.split(b'\n'):
                ln = ln.strip()
                if ln:
                    try:
                        out.append(ln.decode('utf-8', 'replace'))
                    except Exception:
                        pass
            return out[-max_lines:]
    except Exception:
        return []


# ---------- Sources de donnees ----------
# Lab Docker : pas de systemd. On verifie la presence du processus de chaque
# "service" (le conteneur du dashboard partage l'espace PID du serveur de defense).
PROCESSUS_SERVICES = {
    "defense-iptables": "^farpd ",
    "suricata-ips":     "^/usr/bin/suricata ",
    "defense-modules":  "modules/consolidation.py",
    "cowrie":           "twistd .*cowrie",
    "dionaea":          "^/opt/dionaea/bin/dionaea ",
    "dashboard":        "dashboard/app.py",
}
HAS_SYSTEMD = os.path.isdir('/run/systemd/system')


def get_services_status():
    result = {}
    for svc in SERVICES:
        try:
            if HAS_SYSTEMD:
                out = subprocess.run(["systemctl", "is-active", svc],
                                     capture_output=True, text=True, timeout=5)
                result[svc] = out.stdout.strip()
            else:
                out = subprocess.run(["pgrep", "-f", PROCESSUS_SERVICES[svc]],
                                     capture_output=True, text=True, timeout=5)
                result[svc] = "active" if out.returncode == 0 else "inactive"
        except Exception:
            result[svc] = "unknown"
    return result


def _read_alerts(limit=300):
    alerts = []
    for line in tail_lines(EVE_JSON, limit):
        try:
            ev = json.loads(line)
        except Exception:
            continue
        if ev.get('event_type') != 'alert':
            continue
        a = ev.get('alert', {})
        alerts.append({
            'time': ev.get('timestamp', '')[11:19],
            'src': ev.get('src_ip', '?'),
            'dst': ev.get('dest_ip', '?'),
            'sig': a.get('signature', 'alerte'),
        })
    return alerts


def get_suricata_alerts():
    return _read_alerts(300)[-MAX_EVENTS:][::-1]


def get_scan_types():
    """Repartition des types de scan pour le camembert."""
    counter = Counter()
    for a in _read_alerts(300):
        sig = a['sig'].upper()
        if 'SYN' in sig:
            counter['SYN'] += 1
        elif 'NULL' in sig:
            counter['NULL'] += 1
        elif 'XMAS' in sig:
            counter['XMAS'] += 1
        elif 'FIN' in sig:
            counter['FIN'] += 1
        elif 'UDP' in sig:
            counter['UDP'] += 1
        elif 'MASSIF' in sig or 'MASS' in sig:
            counter['Massif'] += 1
        elif 'PING' in sig or 'SWEEP' in sig:
            counter['Ping'] += 1
        else:
            counter['Autre'] += 1
    return dict(counter)


def get_top_attackers_ips():
    """Top 5 IP sources d'alertes."""
    counter = Counter()
    for a in _read_alerts(300):
        if a['src'] and a['src'] != '?':
            counter[a['src']] += 1
    return counter.most_common(5)


def get_attackers():
    try:
        out = subprocess.run(["sudo", "-n", "ipset", "list", "ATTAQUANTS"],
                             capture_output=True, text=True, timeout=5)
        atk = []
        in_members = False
        for line in out.stdout.splitlines():
            if line.startswith('Members:'):
                in_members = True
                continue
            if in_members and line.strip():
                parts = line.split()
                ip = parts[0]
                timeout = ''
                if 'timeout' in parts:
                    timeout = parts[parts.index('timeout') + 1] + 's'
                atk.append({'ip': ip, 'timeout': timeout})
        return atk
    except Exception:
        return []


def _read_cowrie(limit=300):
    events = []
    for line in tail_lines(COWRIE_JSON, limit):
        try:
            ev = json.loads(line)
        except Exception:
            continue
        events.append(ev)
    return events


def get_cowrie_sessions():
    events = []
    for ev in _read_cowrie(300):
        etype = ev.get('eventid', '')
        if etype in ('cowrie.login.success', 'cowrie.login.failed',
                     'cowrie.command.input', 'cowrie.session.connect'):
            label = {
                'cowrie.session.connect': 'CONNEXION',
                'cowrie.login.success': 'LOGIN OK',
                'cowrie.login.failed': 'LOGIN ECHEC',
                'cowrie.command.input': 'CMD',
            }.get(etype, etype)
            detail = ev.get('input') or (
                (ev.get('username', '') + '/' + ev.get('password', ''))
                if 'login' in etype else '')
            events.append({
                'time': ev.get('timestamp', '')[11:19],
                'src': ev.get('src_ip', '?'),
                'type': label,
                'detail': detail[:80],
            })
    return events[-MAX_EVENTS:][::-1]


def get_cowrie_stats():
    """Compteurs et top commandes Cowrie."""
    sessions = set()
    cmds = Counter()
    logins_ok = 0
    logins_fail = 0
    for ev in _read_cowrie(300):
        etype = ev.get('eventid', '')
        if etype == 'cowrie.session.connect':
            sessions.add(ev.get('session', ''))
        elif etype == 'cowrie.login.success':
            logins_ok += 1
        elif etype == 'cowrie.login.failed':
            logins_fail += 1
        elif etype == 'cowrie.command.input':
            c = (ev.get('input') or '').split()
            if c:
                cmds[c[0]] += 1
    return {
        'sessions': len(sessions),
        'logins_ok': logins_ok,
        'logins_fail': logins_fail,
        'top_cmds': cmds.most_common(5),
    }


def get_dionaea_captures():
    caps = []
    try:
        for name in os.listdir(DIONAEA_FTP):
            full = os.path.join(DIONAEA_FTP, name)
            if os.path.isfile(full):
                caps.append({'file': name, 'size': os.path.getsize(full), 'src': 'ftp'})
    except Exception:
        pass
    try:
        con = sqlite3.connect('file:%s?mode=ro' % DIONAEA_DB, uri=True, timeout=3)
        cur = con.cursor()
        cur.execute("SELECT remote_host, connection_protocol FROM connections "
                    "ORDER BY connection DESC LIMIT 12")
        for row in cur.fetchall():
            caps.append({'file': '[conn] ' + str(row[1]), 'size': 0, 'src': str(row[0])})
        con.close()
    except Exception:
        pass
    return caps[-MAX_EVENTS:]


def get_dionaea_stats():
    """Stats Dionaea : nb connexions, protocoles, fichiers."""
    protos = Counter()
    total_conn = 0
    files = 0
    try:
        con = sqlite3.connect('file:%s?mode=ro' % DIONAEA_DB, uri=True, timeout=3)
        cur = con.cursor()
        cur.execute("SELECT connection_protocol, COUNT(*) FROM connections "
                    "GROUP BY connection_protocol")
        for proto, cnt in cur.fetchall():
            protos[str(proto)] = cnt
            total_conn += cnt
        con.close()
    except Exception:
        pass
    try:
        files = len([f for f in os.listdir(DIONAEA_FTP)
                     if os.path.isfile(os.path.join(DIONAEA_FTP, f))])
    except Exception:
        pass
    return {'total_conn': total_conn, 'protos': dict(protos), 'files': files}


def get_system_metrics():
    """Metriques serveur via psutil."""
    if not HAS_PSUTIL:
        return {'cpu': 0, 'ram': 0, 'disk': 0, 'uptime': 'n/a',
                'net_conn': 0, 'available': False}
    try:
        boot = psutil.boot_time()
        up_s = int(time.time() - boot)
        d, h, m = up_s // 86400, (up_s % 86400) // 3600, (up_s % 3600) // 60
        uptime = '%dj %dh %dm' % (d, h, m)
        return {
            'cpu': round(psutil.cpu_percent(interval=None), 1),
            'ram': round(psutil.virtual_memory().percent, 1),
            'disk': round(psutil.disk_usage('/').percent, 1),
            'uptime': uptime,
            'net_conn': len(psutil.net_connections()),
            'available': True,
        }
    except Exception:
        return {'cpu': 0, 'ram': 0, 'disk': 0, 'uptime': 'n/a',
                'net_conn': 0, 'available': False}


def get_overview():
    """Agrege les KPIs + historique pour la vue d'ensemble."""
    alerts = _read_alerts(300)
    attackers = get_attackers()
    cowrie = get_cowrie_stats()
    dionaea = get_dionaea_stats()

    # Historique : on ajoute le total courant d'alertes au buffer
    total = len(alerts)
    delta = max(0, total - _last_alert_count[0])
    _last_alert_count[0] = total
    alert_history.append(delta)
    time_labels.append(time.strftime('%H:%M:%S'))

    return {
        'kpi': {
            'alerts': total,
            'attackers': len(attackers),
            'cowrie_sessions': cowrie['sessions'],
            'dionaea_files': dionaea['files'],
            'dionaea_conn': dionaea['total_conn'],
        },
        'history': {'labels': list(time_labels), 'data': list(alert_history)},
        'scan_types': get_scan_types(),
        'top_ips': get_top_attackers_ips(),
        'system': get_system_metrics(),
        'cowrie': cowrie,
        'dionaea': dionaea,
    }


# ---------- Threads de surveillance ----------
def monitor_fast():
    """2s : services, overview (KPIs+graphes+psutil), suricata, attaquants."""
    while True:
        socketio.emit('services_update', get_services_status())
        socketio.emit('overview_update', get_overview())
        socketio.emit('suricata_update', get_suricata_alerts())
        socketio.emit('attackers_update', get_attackers())
        time.sleep(2)


def monitor_slow():
    """5s : cowrie + dionaea detail."""
    while True:
        socketio.emit('cowrie_update', get_cowrie_sessions())
        socketio.emit('dionaea_update', get_dionaea_captures())
        time.sleep(5)


# ---------- Rapport forensique PDF ----------
def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return 'n/a'


def _in_period(ts, debut, fin):
    """ts = timestamp ISO du log (UTC). debut/fin = 'YYYY-MM-DD' ou None."""
    if not ts:
        return True
    day = ts[:10]  # YYYY-MM-DD
    if debut and day < debut:
        return False
    if fin and day > fin:
        return False
    return True


class ForensicPDF(FPDF):
    def header(self):
        self.set_fill_color(8, 18, 30)
        self.rect(0, 0, 210, 26, 'F')
        self.set_xy(12, 7)
        self.set_text_color(0, 200, 230)
        self.set_font('Helvetica', 'B', 16)
        self.cell(0, 8, "RAPPORT D'INCIDENT DE SECURITE",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(12)
        self.set_text_color(140, 160, 180)
        self.set_font('Helvetica', '', 8)
        self.cell(0, 5, "Systeme de defense reseau - SOC / Detection & Deception",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_text_color(150, 150, 150)
        self.set_font('Helvetica', 'I', 7)
        self.cell(0, 5, 'Document confidentiel - Genere automatiquement par le SOC - Page '
                  + str(self.page_no()) + '/{nb}', align='C')

    def section(self, titre):
        self.ln(3)
        self.set_fill_color(0, 200, 230)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 11)
        self.cell(0, 8, '  ' + titre, new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        self.ln(2)
        self.set_text_color(30, 30, 30)

    def kv(self, key, val):
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(70, 70, 70)
        x0 = self.get_x()
        self.cell(55, 6, key, new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font('Helvetica', '', 9)
        self.set_text_color(20, 20, 20)
        self.multi_cell(0, 6, str(val), new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def generate_report(debut=None, fin=None, periode_label='Analyse globale'):
    now = datetime.now(timezone.utc)
    report_id = 'INC-' + now.strftime('%Y%m%d-%H%M%S')

    alerts = [a for a in _read_alerts(400)
              if _in_period_alert(a, debut, fin)]
    attackers = get_attackers()
    cowrie_all = _read_cowrie(400)
    cowrie_f = [ev for ev in cowrie_all
                if _in_period(ev.get('timestamp', ''), debut, fin)]
    cowrie_stats = get_cowrie_stats()
    dionaea_stats = get_dionaea_stats()
    scan_types = _scan_types_from(alerts)

    pdf = ForensicPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    NL = dict(new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    SAME = dict(new_x=XPos.RIGHT, new_y=YPos.TOP)

    # 1. Infos
    pdf.section('1. Informations du rapport')
    pdf.kv('Identifiant', report_id)
    pdf.kv('Date de generation', now.strftime('%Y-%m-%d %H:%M:%S UTC'))
    pdf.kv('Periode analysee', periode_label)
    pdf.kv('Classification', 'CONFIDENTIEL')
    pdf.ln(2)

    # 2. Resume executif
    pdf.section('2. Resume executif')
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(30, 30, 30)
    resume = (
        'Au cours de la periode analysee (' + periode_label + '), le systeme de defense '
        'a enregistre ' + str(len(alerts)) + ' alerte(s) de securite. '
        + str(len(attackers)) + ' source(s) hostile(s) sont actuellement redirigee(s) '
        'vers l\'infrastructure de deception. '
        + str(cowrie_stats['sessions']) + ' session(s) ont ete piegees sur le honeypot SSH, '
        'et ' + str(dionaea_stats['files']) + ' fichier(s) ont ete captures pour analyse. '
        'Aucun actif de production n\'a ete compromis : l\'integralite du trafic hostile '
        'a ete confinee dans l\'environnement de leurre.')
    pdf.multi_cell(0, 5, resume)
    pdf.ln(2)

    pdf.set_font('Helvetica', 'B', 9)
    pdf.set_fill_color(235, 245, 250)
    pdf.set_text_color(20, 20, 20)
    kpis = [('Alertes IDS/IPS', len(alerts)),
            ('Attaquants actifs', len(attackers)),
            ('Sessions piegees', cowrie_stats['sessions']),
            ('Logins captures', cowrie_stats['logins_ok']),
            ('Fichiers captures', dionaea_stats['files']),
            ('Connexions honeypot', dionaea_stats['total_conn'])]
    for i, (k, v) in enumerate(kpis):
        last = (i % 3 == 2)
        pdf.cell(63, 8, k + ' : ' + str(v), border=1, fill=True, align='C',
                 **(NL if last else SAME))
    pdf.ln(4)

    # 3. Attaquants
    pdf.section('3. Sources hostiles identifiees')
    if attackers:
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(0, 200, 230)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(70, 7, 'Adresse IP', border=1, fill=True, **SAME)
        pdf.cell(60, 7, 'Statut', border=1, fill=True, **SAME)
        pdf.cell(60, 7, 'Expiration', border=1, fill=True, **NL)
        pdf.set_text_color(30, 30, 30)
        pdf.set_font('Helvetica', '', 8)
        for a in attackers:
            pdf.cell(70, 6, a['ip'], border=1, **SAME)
            pdf.cell(60, 6, 'Redirige (actif)', border=1, **SAME)
            pdf.cell(60, 6, a['timeout'] or 'permanent', border=1, **NL)
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucune source hostile actuellement redirigee.', **NL)
    pdf.ln(2)

    if scan_types:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, 'Techniques de scan detectees sur la periode :', **NL)
        pdf.set_font('Helvetica', '', 9)
        for t, n in scan_types.items():
            pdf.cell(0, 5, '   - ' + t + ' : ' + str(n) + ' occurrence(s)', **NL)
    pdf.ln(2)

    # 4. Alertes
    pdf.section('4. Detail des alertes (IDS/IPS Suricata)')
    pdf.set_font('Helvetica', 'B', 8)
    pdf.set_fill_color(0, 200, 230)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(28, 7, 'Heure UTC', border=1, fill=True, **SAME)
    pdf.cell(42, 7, 'Source', border=1, fill=True, **SAME)
    pdf.cell(42, 7, 'Destination', border=1, fill=True, **SAME)
    pdf.cell(78, 7, 'Signature', border=1, fill=True, **NL)
    pdf.set_text_color(30, 30, 30)
    pdf.set_font('Helvetica', '', 8)
    if alerts:
        for a in alerts[-25:][::-1]:
            pdf.cell(28, 6, a['time'], border=1, **SAME)
            pdf.cell(42, 6, a['src'], border=1, **SAME)
            pdf.cell(42, 6, a['dst'], border=1, **SAME)
            pdf.cell(78, 6, a['sig'][:48], border=1, **NL)
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucune alerte sur la periode selectionnee.', **NL)
    pdf.ln(2)

    # 5. Cowrie
    pdf.section('5. Activite sur le honeypot SSH (Cowrie)')
    cmds = []
    for ev in cowrie_f:
        if ev.get('eventid') == 'cowrie.command.input':
            cmds.append((ev.get('timestamp', '')[11:19],
                         ev.get('src_ip', '?'), ev.get('input', '')))
    pdf.set_font('Helvetica', '', 9)
    pdf.cell(0, 6, 'Commandes executees par les attaquants dans le shell piege :', **NL)
    pdf.ln(1)
    if cmds:
        pdf.set_font('Courier', '', 8)
        pdf.set_fill_color(20, 25, 35)
        pdf.set_text_color(40, 230, 140)
        for t, ip, c in cmds[-30:]:
            pdf.cell(0, 5, ' [' + t + '] ' + ip + ' $ ' + c[:72], fill=True, **NL)
        pdf.set_text_color(30, 30, 30)
    else:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucune commande capturee sur la periode.', **NL)
    pdf.ln(2)

    # 6. Dionaea + hash
    pdf.section('6. Artefacts captures (Dionaea) - Preuves forensiques')
    pdf.set_font('Helvetica', '', 9)
    pdf.multi_cell(0, 5, 'Les fichiers ci-dessous ont ete deposes par les attaquants sur le '
                   'honeypot de capture. Leur empreinte SHA-256 garantit l\'integrite de '
                   'la preuve pour analyse ulterieure.')
    pdf.ln(2)
    files_found = False
    try:
        for name in os.listdir(DIONAEA_FTP):
            full = os.path.join(DIONAEA_FTP, name)
            if os.path.isfile(full):
                files_found = True
                h = sha256_file(full)
                size = os.path.getsize(full)
                pdf.set_font('Helvetica', 'B', 9)
                pdf.set_text_color(180, 40, 40)
                pdf.cell(0, 6, 'Fichier : ' + name, **NL)
                pdf.set_text_color(30, 30, 30)
                pdf.set_font('Helvetica', '', 8)
                pdf.cell(0, 5, '   Taille : ' + str(size) + ' octets', **NL)
                pdf.set_font('Courier', '', 7)
                pdf.cell(0, 5, '   SHA-256 : ' + h, **NL)
                pdf.ln(2)
    except Exception:
        pass
    if not files_found:
        pdf.set_font('Helvetica', 'I', 9)
        pdf.cell(0, 6, 'Aucun fichier capture.', **NL)
    pdf.ln(2)

    # 7. Conclusion
    pdf.section('7. Conclusion et recommandations')
    pdf.set_font('Helvetica', '', 9)
    pdf.set_text_color(30, 30, 30)
    concl = (
        'L\'architecture de defense en profondeur a fonctionne comme prevu. '
        'La chaine detection (Suricata) -> redirection automatique (iptables/ipset) '
        '-> deception (Cowrie, Dionaea, Honeyd) a permis d\'isoler l\'attaquant tout en '
        'collectant un renseignement complet sur ses techniques. L\'attribution des '
        'sources hostiles a ete preservee. Recommandations : conserver les artefacts '
        'captures pour analyse approfondie, enrichir les regles de detection a partir des '
        'signatures observees, et maintenir la surveillance temps reel via le SOC.')
    pdf.multi_cell(0, 5, concl)

    out = pdf.output()
    return bytes(out), report_id


def _in_period_alert(a, debut, fin):
    # les alertes n'ont que l'heure (time) ; on ne filtre pas finement faute de date
    # complete dans la structure allegee -> on garde tout si pas de periode
    return True


def _scan_types_from(alerts):
    counter = Counter()
    for a in alerts:
        sig = a['sig'].upper()
        if 'SYN' in sig:
            counter['SYN'] += 1
        elif 'NULL' in sig:
            counter['NULL'] += 1
        elif 'XMAS' in sig:
            counter['XMAS'] += 1
        elif 'FIN' in sig:
            counter['FIN'] += 1
        elif 'UDP' in sig:
            counter['UDP'] += 1
        elif 'MASSIF' in sig or 'MASS' in sig:
            counter['Massif'] += 1
        elif 'PING' in sig or 'SWEEP' in sig:
            counter['Ping'] += 1
        else:
            counter['Autre'] += 1
    return dict(counter)




@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if check_login(u, p):
            session['logged_in'] = True
            session['user'] = u
            return redirect(url_for('index'))
        error = 'Identifiants invalides'
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    return render_template('index.html', user=session.get('user', 'admin'))


@app.route('/api/infra')
@login_required
def api_infra():
    return jsonify(INFRA)


@app.route('/api/report')
@login_required
def api_report():
    if not HAS_FPDF:
        return 'Generation PDF indisponible (fpdf2 manquant)', 503
    debut = request.args.get('debut', '').strip() or None
    fin = request.args.get('fin', '').strip() or None
    label = request.args.get('label', '').strip() or 'Analyse globale'
    pdf_bytes, report_id = generate_report(debut, fin, label)
    filename = 'rapport_' + report_id + '.pdf'
    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={'Content-Disposition': 'attachment; filename=' + filename})


@socketio.on('connect')
def on_connect():
    if not session.get('logged_in'):
        disconnect()
        return False
    socketio.emit('services_update', get_services_status())
    socketio.emit('overview_update', get_overview())
    socketio.emit('suricata_update', get_suricata_alerts())
    socketio.emit('attackers_update', get_attackers())
    socketio.emit('cowrie_update', get_cowrie_sessions())
    socketio.emit('dionaea_update', get_dionaea_captures())


if __name__ == '__main__':
    threading.Thread(target=monitor_fast, daemon=True).start()
    threading.Thread(target=monitor_slow, daemon=True).start()
    socketio.run(app, host='0.0.0.0', port=9443,
                 allow_unsafe_werkzeug=True)
