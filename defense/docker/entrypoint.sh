#!/bin/bash
# =============================================================================
# Démarrage du serveur de défense dans Docker.
# Remplace la chaîne systemd de la VM, dans le même ordre :
#   ipset-persistent -> defense-iptables -> wg-quick@wg0 -> suricata-ips
#   -> defense-modules (consolidation, suricata_reader, surveillance, honeyd)
# (voir docs/NOTES.md, section « De systemd à Docker »)
# =============================================================================
set -euo pipefail

IFACE="${DEFENSE_IFACE:-eth0}"
ROUTER_IP="${ROUTER_IP:-192.168.10.1}"
SECRETS=/lab-secrets
STATE=/lab-state

log() { echo "[entrypoint] $*"; }

# --- 0. Prérequis noyau (chargés sur l'hôte : un conteneur ne peut pas le faire)
manquants=""
for m in nfnetlink_queue xt_NFQUEUE ip_set_hash_ip xt_set wireguard; do
    grep -q "^$m " /proc/modules || manquants="$manquants $m"
done
if [ -n "$manquants" ]; then
    # En général le noyau les charge automatiquement à la première utilisation.
    log "info : modules pas encore chargés :$manquants (chargement automatique attendu)"
    log "      en cas d'échec ci-dessous :  make prereqs"
fi

# --- 1. Routage : passerelle = R1 (et non le pont Docker)
ip route replace default via "$ROUTER_IP" dev "$IFACE"
log "route par défaut via R1 ($ROUTER_IP)"

# --- 2. Secrets générés localement au premier démarrage (jamais dans Git)
mkdir -p "$SECRETS" "$STATE"
chmod 700 "$SECRETS"
umask 077
[ -f "$SECRETS/server_wg_private" ] || {
    wg genkey > "$SECRETS/server_wg_private"
    wg pubkey < "$SECRETS/server_wg_private" > "$SECRETS/server_wg_public"
    wg genkey > "$SECRETS/admin_wg_private"
    wg pubkey < "$SECRETS/admin_wg_private" > "$SECRETS/admin_wg_public"
    ssh-keygen -q -t ed25519 -N "" -C "admin-lab" -f "$SECRETS/admin_ssh_key"
    log "clés WireGuard et SSH générées dans le volume lab-secrets"
}
[ -f "$SECRETS/ssh_host_ed25519_key" ] || \
    ssh-keygen -q -t ed25519 -N "" -f "$SECRETS/ssh_host_ed25519_key"
cp "$SECRETS"/ssh_host_ed25519_key* /etc/ssh/
chmod a+r "$SECRETS"/*.pub "$SECRETS"/*_public

# Le vrai sshd du serveur : accès par clé uniquement (compte « server »)
install -d -m 700 -o server -g server /home/server/.ssh
install -m 600 -o server -g server "$SECRETS/admin_ssh_key.pub" /home/server/.ssh/authorized_keys

# wg0.conf au même format que « vpn_admin.sh installer » + « vpn_admin.sh ajouter »
mkdir -p /etc/wireguard
cp "$SECRETS/server_wg_private" /etc/wireguard/privatekey
cp "$SECRETS/server_wg_public"  /etc/wireguard/publickey
cat > /etc/wireguard/wg0.conf <<WG
# /etc/wireguard/wg0.conf — généré au démarrage du conteneur
[Interface]
Address    = 10.99.0.1/24
ListenPort = 51820
PrivateKey = $(cat "$SECRETS/server_wg_private")
PostUp     = bash /home/server/vpn_admin.sh pare-feu-up
PostDown   = bash /home/server/vpn_admin.sh pare-feu-down

# admin: admin-lab
[Peer]
PublicKey  = $(cat "$SECRETS/admin_wg_public")
AllowedIPs = 10.99.0.2/32
WG
umask 022

# --- 3. Règles iptables + ipset + leurres Honeyd (script d'origine)
DEFENSE_IFACE="$IFACE" bash /home/server/setup_iptables.sh

# --- 4. Persistance ipset (ipset-persistent.service) : restauration APRÈS la
#        création des ensembles, sinon « ipset destroy » effacerait les membres.
if [ -s "$STATE/ipset.rules" ]; then
    grep '^add ATTAQUANTS ' "$STATE/ipset.rules" | ipset restore -exist || true
    log "attaquants restaurés : $(grep -c '^add ATTAQUANTS ' "$STATE/ipset.rules" || true)"
fi

# --- 5. Accès au dashboard depuis la machine hôte (option du lab, désactivable)
if [ "${DASHBOARD_FROM_HOST:-1}" = "1" ]; then
    HOST_GW="${HOST_GATEWAY:-192.168.10.254}"
    iptables -I INPUT 1 -p tcp --dport 9443 -s "$HOST_GW" -d 192.168.10.10 -j ACCEPT
    log "dashboard joignable depuis l'hôte ($HOST_GW -> 192.168.10.10:9443)"
fi

# --- 6. Tunnel d'administration (wg-quick@wg0 ; PostUp = vpn_admin.sh pare-feu-up)
wg-quick down wg0 >/dev/null 2>&1 || true
wg-quick up wg0
log "WireGuard wg0 actif (10.99.0.1, udp/51820)"

# --- 7. Suricata + modules Python + sshd sous supervisord
rm -f /var/run/suricata.pid /home/server/defense_system/sockets/consolidation.sock
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
