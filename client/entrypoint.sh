#!/bin/sh
# Passerelle = R1 (.1 du VLAN), comme le DHCP de R1 le distribuait
ip route replace default via "$GATEWAY"
echo "[$(hostname)] passerelle $GATEWAY"
exec sleep infinity
