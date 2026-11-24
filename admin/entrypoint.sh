#!/bin/bash
# Client WireGuard : même configuration que le poste Kali du mémoire (figure 10)
set -euo pipefail
ip route replace default via "$GATEWAY"

mkdir -p /etc/wireguard ~/.ssh
umask 077
cat > /etc/wireguard/wg0.conf <<WG
[Interface]
PrivateKey = $(cat /lab-secrets/admin_wg_private)
Address    = 10.99.0.2/32

[Peer]
PublicKey  = $(cat /lab-secrets/server_wg_public)
Endpoint   = ${VPN_ENDPOINT}
AllowedIPs = 10.99.0.1/32
PersistentKeepalive = 25
WG
cp /lab-secrets/admin_ssh_key ~/.ssh/id_ed25519
printf 'Host 10.99.0.1 192.168.10.10\n  User server\n  StrictHostKeyChecking accept-new\n' > ~/.ssh/config
wg-quick up wg0
echo "[admin] tunnel WireGuard actif — essai : ssh 10.99.0.1"
exec sleep infinity
