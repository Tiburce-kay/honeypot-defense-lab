# R1 : remplace le Cisco c7200 (IOS non redistribuable) par un routeur Linux.
# Mêmes passerelles .1 dans chaque VLAN, NAT vers l'extérieur, redirection udp/51820.
FROM alpine:3.20
RUN apk add --no-cache iptables iproute2 bash tcpdump
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
