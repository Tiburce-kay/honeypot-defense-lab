#!/bin/bash
# Prêt = Suricata lié à la file NFQUEUE 0, consolidateur à l'écoute, leurres en place
pgrep -f "^/usr/bin/suricata" >/dev/null || exit 1
grep -qE '^ *0 ' /proc/net/netfilter/nfnetlink_queue 2>/dev/null || exit 1
[ -S /home/server/defense_system/sockets/consolidation.sock ] || exit 1
ip -4 addr show | grep -q '192.168.10.50/' || exit 1
