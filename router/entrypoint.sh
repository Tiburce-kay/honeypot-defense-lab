#!/bin/bash
# Configuration de R1 (voir docs/gns3-original/R1.cfg pour la version Cisco)
set -euo pipefail

iface_of() { ip -4 -o addr show | awk -v ip="$1" '$4 ~ "^"ip"/" {print $2}'; }

WAN_IF=$(iface_of "$WAN_IP")
ip route replace default via "$WAN_GW" dev "$WAN_IF"

# Routage inter-VLAN (sous-interfaces Fa0/0.10/.20/.30/.40/.99 sur le Cisco)
sysctl -qw net.ipv4.ip_forward=1 || true

# ip route 192.168.20.20 255.255.255.255 192.168.10.10
# Le leurre « serveur applicatif » du VLAN 20 est porté par le serveur de défense :
# le trafic qui lui est destiné doit traverser l'IPS.
ip route replace 192.168.20.20/32 via 192.168.10.10

# ip nat inside source list 1 interface GigabitEthernet1/0 overload
for net in 192.168.10.0/24 192.168.20.0/24 192.168.30.0/24 192.168.40.0/24 192.168.99.0/24; do
    iptables -t nat -A POSTROUTING -s "$net" -o "$WAN_IF" -j MASQUERADE
done

# ip nat inside source static udp 192.168.10.10 51820 interface Gi1/0 51820
iptables -t nat -A PREROUTING -i "$WAN_IF" -p udp --dport 51820 \
    -j DNAT --to-destination 192.168.10.10:51820

echo "[R1] prêt — WAN $WAN_IF ($WAN_IP), routage inter-VLAN actif"
ip -4 -br addr
exec sleep infinity
