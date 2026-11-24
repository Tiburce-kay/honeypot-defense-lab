# Poste d'administration (VLAN 99) avec client WireGuard — remplace la VM « Administrateur »
FROM alpine:3.20
RUN apk add --no-cache wireguard-tools bash iproute2 iputils openssh-client curl
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
