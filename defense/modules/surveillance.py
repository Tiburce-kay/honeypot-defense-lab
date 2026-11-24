#!/usr/bin/env python3
"""
Module 1 — Surveillance du trafic reseau (observateur passif).

ROLE : Capturer et journaliser les scans reseau.
       N'applique AUCUNE regle iptables.
       N'envoie PAS de signal au consolidateur.
       Suricata IPS est le seul decideur.

Ce module sert a :
  - Avoir une vue complementaire a Suricata (paquets que Suricata ne voit pas)
  - Journaliser les tentatives de scan avec details (ports, flags)
  - Alimenter le dashboard Flask avec des donnees temps reel

Auteur  : [Ton nom]
Date    : 2026
Version : 3.0 — passif uniquement
"""

import os
import json
import socket
import logging
import ipaddress
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

INTERFACE   = "enp0s3"
IP_SERVEUR  = "192.168.10.10"
VLAN_ADMIN  = ipaddress.ip_network("192.168.99.0/24")
SEUIL_PORTS = 5      # Reduit : on log plus tot (Suricata a deja agi)
SEUIL_TEMPS = 30
COOLDOWN    = 3.0

BASE_DIR    = "/home/server/defense_system"
LOG_DIR     = os.path.join(BASE_DIR, "logs")
LOG_FILE    = os.path.join(LOG_DIR, "surveillance.log")
SOCKET_PATH = os.path.join(BASE_DIR, "sockets", "consolidation.sock")

FLAGS_NORMAUX = {0x010, 0x018, 0x011, 0x019}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)

logger = logging.getLogger("surveillance")
logger.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s",
                        "%Y-%m-%d %H:%M:%S")
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setLevel(logging.DEBUG); fh.setFormatter(fmt)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO);  ch.setFormatter(fmt)
logger.addHandler(fh); logger.addHandler(ch)


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------

connexions:     dict = {}
derniere_alerte: dict = {}


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def identifier_type_scan(flags) -> str:
    try:
        v = int(flags)
        return {
            0x000: "NULL scan  (-sN)",
            0x001: "FIN scan   (-sF)",
            0x002: "SYN scan   (-sS)",
            0x029: "XMAS scan  (-sX)",
        }.get(v, f"TCP inconnu (flags=0x{v:03x})")
    except (TypeError, ValueError):
        return "Type indetermine"


def est_suspect(flags) -> bool:
    try:
        return int(flags) not in FLAGS_NORMAUX
    except (TypeError, ValueError):
        return False


def est_administrateur(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in VLAN_ADMIN
    except ValueError:
        return False


def en_cooldown(ip: str) -> bool:
    if ip not in derniere_alerte:
        return False
    return time.time() - derniere_alerte[ip] < COOLDOWN


def nettoyer_timestamps(ts: list, now: float) -> list:
    return [t for t in ts if now - t <= SEUIL_TEMPS]


# ---------------------------------------------------------------------------
# Journalisation (PASSIF — pas d'action iptables)
# ---------------------------------------------------------------------------

def journaliser_detection(ip_src: str, type_scan: str,
                           proto: str, ports: list) -> None:
    """
    Journalise la detection et envoie au consolidateur pour le dashboard.
    N'applique AUCUNE regle iptables — c'est le role de Suricata.
    """
    admin  = est_administrateur(ip_src)
    statut = "SCAN AUTORISE" if admin else "POTENTIEL ATTAQUANT"
    sep    = "-" * 55

    logger.warning(
        f"\n{sep}\n"
        f"STATUT   : {statut}\n"
        f"IP       : {ip_src}\n"
        f"Type     : {type_scan}\n"
        f"Proto    : {proto}\n"
        f"Ports    : {sorted(ports)}\n"
        f"Heure    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Note     : Suricata IPS a deja agi sur ces paquets\n"
        f"{sep}"
    ) if not admin else logger.info(
        f"\n{sep}\nSTATUT : {statut}\nIP : {ip_src}\n{sep}"
    )

    # Envoyer au consolidateur pour le dashboard uniquement
    # Le flag "source":"scapy_passif" indique que c'est informatif
    detection = {
        "horodatage" : datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "ip_source"  : ip_src,
        "type_scan"  : type_scan,
        "protocole"  : proto,
        "est_admin"  : admin,
        "source"     : "scapy_passif",   # <-- IMPORTANT : pas de decision
        "ports"      : sorted(ports),
    }
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.sendto(json.dumps(detection).encode(), SOCKET_PATH)
        sock.close()
    except (OSError, ConnectionRefusedError):
        pass  # Consolidateur absent = pas critique en mode passif

    derniere_alerte[ip_src] = time.time()


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

def tracker_connexion(ip_src: str, port_dst: int,
                       flags, proto: str) -> None:
    if en_cooldown(ip_src):
        return

    now = datetime.now().timestamp()
    if ip_src not in connexions:
        connexions[ip_src] = {"ports": set(), "timestamps": [], "type_scan": ""}

    t = connexions[ip_src]
    if port_dst is not None:
        t["ports"].add(port_dst)
    t["timestamps"].append(now)
    t["timestamps"] = nettoyer_timestamps(t["timestamps"], now)
    if flags is not None:
        t["type_scan"] = identifier_type_scan(flags)

    if len(t["ports"]) >= SEUIL_PORTS:
        journaliser_detection(ip_src, t["type_scan"], proto, list(t["ports"]))
        t["ports"]      = set()
        t["timestamps"] = []


def analyser_paquet(paquet) -> None:
    if not paquet.haslayer(IP):
        return
    ip_src = paquet[IP].src
    ip_dst = paquet[IP].dst
    if ip_dst != IP_SERVEUR or ip_src == IP_SERVEUR:
        return

    proto = port_dst = flags = None

    if paquet.haslayer(TCP):
        flags = paquet[TCP].flags
        if not est_suspect(flags):
            return
        port_dst = paquet[TCP].dport
        proto    = "TCP"
    elif paquet.haslayer(UDP):
        port_dst = paquet[UDP].dport
        proto    = "UDP"
    elif paquet.haslayer(ICMP):
        port_dst = 0
        proto    = "ICMP"
    else:
        return

    tracker_connexion(ip_src, port_dst, flags, proto)


# ---------------------------------------------------------------------------
# Demarrage
# ---------------------------------------------------------------------------

def demarrer_surveillance() -> None:
    logger.info("=" * 55)
    logger.info("Module 1 — Surveillance (mode PASSIF)")
    logger.info("Suricata IPS est le decideur principal")
    logger.info("=" * 55)
    logger.info(f"Interface        : {INTERFACE}")
    logger.info(f"Serveur          : {IP_SERVEUR}")
    logger.info(f"VLAN Admin       : {VLAN_ADMIN}")
    logger.info(f"Seuil log        : {SEUIL_PORTS} ports en {SEUIL_TEMPS}s")
    logger.info(f"Cooldown         : {COOLDOWN}s")
    logger.info("=" * 55)

    # Filtre BPF :
    #   - Trafic vers le serveur uniquement
    #   - Exclure port 2222 : evite de re-detecter le trafic honeypot
    #   - Exclure port 22   : SSH admin, pas de scan
    filtre_bpf = (
        f"dst host {IP_SERVEUR} and "
        "not (tcp dst port 22 or tcp dst port 2222 or "
        "udp dst port 2222)"
    )

    logger.info(f"Filtre BPF : {filtre_bpf}")
    logger.info("=" * 55)

    sniff(iface=INTERFACE, prn=analyser_paquet,
          filter=filtre_bpf, store=False)


if __name__ == "__main__":
    demarrer_surveillance()
