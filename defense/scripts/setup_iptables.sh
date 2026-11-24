#!/bin/bash
# ============================================================
# setup_iptables.sh — VERSION FINALE PROPRE
# ============================================================

# 1. Routage IP
sysctl -w net.ipv4.ip_forward=1

# 2. Tout vider proprement
iptables -t nat -F
iptables -t mangle -F
iptables -t filter -F
iptables -X 2>/dev/null || true

# 3. ipsets
ipset destroy ATTAQUANTS 2>/dev/null || true; ipset create ATTAQUANTS hash:ip timeout 3600
ipset destroy HONEYD_IPS 2>/dev/null || true; ipset create HONEYD_IPS hash:ip
ipset add HONEYD_IPS 192.168.10.20 2>/dev/null || true
ipset add HONEYD_IPS 192.168.10.30 2>/dev/null || true
ipset add HONEYD_IPS 192.168.10.40 2>/dev/null || true
ipset add HONEYD_IPS 192.168.20.20 2>/dev/null || true
ipset add HONEYD_IPS 192.168.10.50 2>/dev/null || true

# 4. IPs fictives Honeyd sur enp0s3
ip addr add 192.168.10.20/24 dev enp0s3 2>/dev/null || true
ip addr add 192.168.10.30/24 dev enp0s3 2>/dev/null || true
ip addr add 192.168.10.40/24 dev enp0s3 2>/dev/null || true
ip addr add 192.168.20.20/24 dev enp0s3 2>/dev/null || true
ip addr add 192.168.10.50/24 dev enp0s3 2>/dev/null || true

# ARP pour les IPs fictives
pkill -9 farpd 2>/dev/null; pkill -9 arpd 2>/dev/null; sleep 1
sleep 1
farpd -i enp0s3 192.168.10.20 192.168.10.30 192.168.10.40 192.168.20.20 192.168.10.50 &

# Proxy ARP pour VLAN20
echo 1 > /proc/sys/net/ipv4/conf/enp0s3/proxy_arp 2>/dev/null || true

# 5. Chaîne custom RST
iptables -N BLOCK_RST_OUT 2>/dev/null || true

# ============================================================
# TABLE MANGLE — marquage anti-boucle
# Marque 0x2222 : trafic Cowrie (port 2222) → bypass Suricata
# ============================================================
iptables -t mangle -A PREROUTING -p tcp --dport 2222 -j MARK --set-mark 0x2222
iptables -t mangle -A PREROUTING -p tcp --sport 2222 -j MARK --set-mark 0x2222
iptables -t mangle -A PREROUTING -p udp --dport 2222 -j MARK --set-mark 0x2222

# Marquer aussi les IPs honeyd → bypass Suricata
iptables -t mangle -A PREROUTING -d 192.168.10.20 -j MARK --set-mark 0x2222
iptables -t mangle -A PREROUTING -d 192.168.10.30 -j MARK --set-mark 0x2222
iptables -t mangle -A PREROUTING -d 192.168.10.40 -j MARK --set-mark 0x2222
iptables -t mangle -A PREROUTING -d 192.168.20.20 -j MARK --set-mark 0x2222
iptables -t mangle -A PREROUTING -d 192.168.10.50 -j MARK --set-mark 0x2222
iptables -t mangle -A PREROUTING -p tcp --dport 9443 -j MARK --set-mark 0x2222

# Marquer les attaquants sur port 22 → bypass après DNAT
iptables -t mangle -A PREROUTING \
    -m set --match-set ATTAQUANTS src \
    -p tcp --dport 22 \
    -j MARK --set-mark 0x2222

# Marquer réponses sortantes Cowrie
iptables -t mangle -A OUTPUT -p tcp --sport 2222 -j MARK --set-mark 0x2222

# ============================================================
# TABLE NAT — PREROUTING
# ============================================================

# ── Règle 0 : VLAN admin → RETURN (jamais redirigé) ──────────
iptables -t nat -I PREROUTING 1 \
    -s 192.168.99.0/24 \
    -p tcp --dport 22 \
    -j RETURN

# ── Règle 0bis : Honeypot Dionaea .50 — port 22 jamais redirigé ──
iptables -t nat -I PREROUTING 2 -d 192.168.10.50 -p tcp --dport 22 -j RETURN
iptables -t nat -I PREROUTING 1 -p tcp --dport 9443 -j RETURN

# ── Règle 1 : ATTAQUANTS détectés → Cowrie (port 22 seulement)
iptables -t nat -A PREROUTING \
    -m set --match-set ATTAQUANTS src \
    -m set ! --match-set HONEYD_IPS dst \
    -p tcp --dport 22 \
    -j DNAT --to-destination 192.168.10.10:2222

# ── Règle 2 : ATTAQUANTS → autres ports TCP vers Cowrie ──────
iptables -t nat -A PREROUTING \
    -m set --match-set ATTAQUANTS src \
    -m set ! --match-set HONEYD_IPS dst \
    -p tcp --dport 23:2221 \
    -j DNAT --to-destination 192.168.10.10:2222

iptables -t nat -A PREROUTING \
    -m set --match-set ATTAQUANTS src \
    -m set ! --match-set HONEYD_IPS dst \
    -p tcp --dport 2223:65535 \
    -j DNAT --to-destination 192.168.10.10:2222

# ── Règle 3 : ATTAQUANTS UDP/ICMP → Cowrie ───────────────────
iptables -t nat -A PREROUTING \
    -m set --match-set ATTAQUANTS src \
    -m set ! --match-set HONEYD_IPS dst \
    -p udp \
    -j DNAT --to-destination 192.168.10.10:2222

iptables -t nat -A PREROUTING \
    -m set --match-set ATTAQUANTS src \
    -m set ! --match-set HONEYD_IPS dst \
    -p icmp \
    -j DNAT --to-destination 192.168.10.10

# ── Règle 4 : Honeyd 192.168.20.20 — port 22 UNIQUEMENT → Cowrie
# Les autres ports (80/443/8443) restent sur honeyd pour nmap réaliste
iptables -t nat -A PREROUTING \
    -d 192.168.20.20 \
    -p tcp --dport 22 \
    -j DNAT --to-destination 192.168.10.10:2222

# ── Règle 5 : Honeyd 192.168.10.20/30/40 — port 22 → Cowrie ─
iptables -t nat -A PREROUTING \
    -d 192.168.10.20 \
    -p tcp --dport 22 \
    -j DNAT --to-destination 192.168.10.10:2222

iptables -t nat -A PREROUTING \
    -d 192.168.10.30 \
    -p tcp --dport 22 \
    -j DNAT --to-destination 192.168.10.10:2222

iptables -t nat -A PREROUTING \
    -d 192.168.10.40 \
    -p tcp --dport 22 \
    -j DNAT --to-destination 192.168.10.10:2222

# ── Règle 6 : DNAT universel SSH → Cowrie ────────────────────
# Tout SSH entrant (port 22) → Cowrie
# Même sans scan préalable, l'attaquant tombe sur Cowrie
# SAUF VLAN admin (déjà géré par RETURN en règle 0)
iptables -t nat -A PREROUTING \
    -p tcp --dport 22 \
    -j DNAT --to-destination 192.168.10.10:2222

# ── SNAT retour Cowrie ────────────────────────────────────────
iptables -t nat -A POSTROUTING \
    -p tcp --sport 2222 \
    -o enp0s3 \
    -j SNAT --to-source 192.168.10.10

# ============================================================
# TABLE FILTER — INPUT
# ============================================================
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Honeyd IPs → accepter directement
iptables -A INPUT -d 192.168.10.20 -j ACCEPT
iptables -A INPUT -d 192.168.10.30 -j ACCEPT
iptables -A INPUT -d 192.168.10.40 -j ACCEPT
iptables -A INPUT -d 192.168.20.20 -j ACCEPT

# Trafic marqué 0x2222 (Cowrie/Honeyd) → ACCEPT, bypass Suricata
# Dashboard SOC 9443 : acces admin uniquement (VLAN99 + hote dev)
iptables -A INPUT -p tcp --dport 9443 -s 192.168.99.2 -j ACCEPT
iptables -A INPUT -p tcp --dport 9443 -j DROP
iptables -A INPUT -m mark --mark 0x2222 -j ACCEPT

# Tout le reste → Suricata
iptables -A INPUT  -m mark ! --mark 0x2222 -j NFQUEUE --queue-num 0 --queue-bypass
iptables -A FORWARD -m mark ! --mark 0x2222 -j NFQUEUE --queue-num 0 --queue-bypass

# Bloquer RST sortants vers attaquants
iptables -A OUTPUT -p tcp --tcp-flags RST RST \
    -m set --match-set ATTAQUANTS dst -j DROP

# Bloquer accès direct port 2222 depuis extérieur
iptables -I INPUT 1 -p tcp --dport 2222 -m state --state NEW ! -d 192.168.10.10 -j DROP

echo "iptables + ipset OK"

# Re-applique les regles du tunnel VPN (prioritaires sur les redirections Cowrie)
systemctl is-active --quiet wg-quick@wg0 && bash /home/server/vpn_admin.sh pare-feu-up || true

# Garde du tableau de bord (port 9443) : injoignable sur les adresses des leurres
bash /home/server/vpn_admin.sh garde-tableau || true
