#!/usr/bin/env bash
# =============================================================================
# demo.sh — Rejoue les expériences du projet de recherche, de bout en bout.
#   1. Reconnaissance nmap depuis le VLAN Visiteurs -> détection Suricata
#   2. Redirection dynamique : l'attaquant est inscrit dans l'ipset ATTAQUANTS
#   3. Session SSH piégée dans Cowrie (root/root sur « srv-prod-01 »)
#   4. Dépôt d'un fichier sur Dionaea (FTP) + empreinte SHA-256
#   5. Administration à distance par le tunnel WireGuard (vrai serveur)
#   6. Exemption du VLAN 99 et isolement du tableau de bord
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

DC="docker compose"
ATK=192.168.40.2
OK=0; KO=0

titre()  { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
ok()     { printf '  \033[32m[OK]\033[0m %s\n' "$*"; OK=$((OK+1)); }
ko()     { printf '  \033[31m[ÉCHEC]\033[0m %s\n' "$*"; KO=$((KO+1)); }
filtre() { grep -vE 'post-quantum|store now|upgraded|WARNING|Warning: Permanently' || true; }

$DC ps --status running --services | grep -qx defense || { echo "Le lab n'est pas démarré : make up"; exit 1; }

titre "0. État initial"
# Repartir d'un état neuf : vider l'ipset et réinitialiser le délai anti-rafale
# (60 s par IP, en mémoire) du module de consolidation.
$DC exec -T defense ipset flush ATTAQUANTS
$DC exec -T defense supervisorctl restart consolidation >/dev/null
sleep 1
echo "  ipset ATTAQUANTS vidé : l'attaquant $ATK n'est pas encore connu"

titre "1. Reconnaissance : nmap -sS depuis la Kali ($ATK, VLAN 40)"
nb_alertes() { $DC exec -T defense sh -c 'cat /var/log/suricata/eve.json 2>/dev/null | grep -c "\"event_type\":\"alert\""'; }
AVANT=$(nb_alertes)
$DC exec -T attacker nmap -sS -Pn -T4 -p 1-200 192.168.10.10 | grep -E "^Nmap done|ports"
sleep 2
APRES=$(nb_alertes)
NOUV=$((APRES - AVANT))
[ "$NOUV" -gt 0 ] && ok "Suricata : $NOUV nouvelles alertes de scan (paquets bloqués en ligne)" \
                  || ko "aucune alerte Suricata"

titre "2. Redirection dynamique (decision.py -> ipset)"
if $DC exec -T defense ipset test ATTAQUANTS "$ATK" 2>/dev/null; then
    ok "$ATK inscrit dans l'ipset ATTAQUANTS : son trafic part vers les leurres"
else
    ko "$ATK absent de l'ipset"
fi
$DC exec -T defense ipset list ATTAQUANTS | sed -n '/Members/,$p' | sed 's/^/  /'

titre "3. Session SSH piégée (Cowrie)"
SORTIE=$($DC exec -T attacker sshpass -p root ssh -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null root@192.168.10.10 'hostname; whoami; ls -al' 2>&1 | filtre)
echo "$SORTIE" | sed 's/^/  kali$ /'
echo "$SORTIE" | grep -q srv-prod-01 && ok "l'attaquant croit être sur srv-prod-01 : c'est Cowrie" \
                                     || ko "session non piégée"
$DC exec -T cowrie sh -c 'grep "cowrie.command.input" var/log/cowrie/cowrie.json | tail -1' \
    | python3 -c 'import sys,json; e=json.loads(sys.stdin.read()); print("  Cowrie a enregistré :", e["src_ip"], "$", e["input"])' 2>/dev/null

titre "4. Capture d'une charge malveillante (Dionaea, FTP 192.168.10.50)"
NOM="malware_capture_test_$(date +%H%M%S).exe"
$DC exec -T attacker sh -c "printf 'MZ fichier de test du lab, inoffensif\n' > /tmp/$NOM && \
    lftp -u root,root -e 'set ftp:passive-mode off; put /tmp/$NOM; bye' ftp://192.168.10.50" >/dev/null 2>&1
EMPREINTE=$($DC exec -T dionaea sh -c "sha256sum var/lib/dionaea/ftp/root/$NOM 2>/dev/null")
[ -n "$EMPREINTE" ] && ok "fichier capturé — SHA-256 : ${EMPREINTE%% *}" || ko "fichier non capturé"

titre "5. Administration à distance par VPN WireGuard (10.99.0.1)"
$DC exec -T admin ping -c1 -W2 10.99.0.1 >/dev/null && ok "ping à travers le tunnel" || ko "tunnel injoignable"
H=$($DC exec -T admin ssh -o BatchMode=yes 10.99.0.1 hostname 2>&1 | filtre)
[ "$H" = "server" ] && ok "SSH via le tunnel : vrai serveur ($H), pas le leurre" || ko "SSH via VPN : '$H'"
C=$($DC exec -T admin curl -s -o /dev/null -w '%{http_code}' http://10.99.0.1:9443/login)
[ "$C" = "200" ] && ok "tableau de bord accessible via le tunnel (HTTP $C)" || ko "dashboard via VPN : HTTP $C"

titre "6. Exemption du VLAN 99 et isolement du tableau de bord"
H=$($DC exec -T admin ssh -o BatchMode=yes 192.168.10.10 hostname 2>&1 | filtre)
[ "$H" = "server" ] && ok "admin (VLAN 99) -> SSH 192.168.10.10 : jamais redirigé" || ko "admin redirigé : '$H'"
C=$($DC exec -T attacker curl -s -m 4 -o /dev/null -w '%{http_code}' http://192.168.10.10:9443/ 2>/dev/null)
[ "$C" = "000" ] && ok "l'attaquant ne peut pas joindre le tableau de bord" || ko "dashboard exposé à l'attaquant (HTTP $C)"

titre "Bilan : $OK réussis, $KO échoués"
echo "  Tableau de bord : http://localhost:9443  (identifiants : make password)"
[ "$KO" -eq 0 ]
