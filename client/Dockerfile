# Postes simples (PC1/PC2 du VLAN 30) — remplacent les VPCS de GNS3
FROM alpine:3.20
RUN apk add --no-cache iproute2 iputils curl openssh-client
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
