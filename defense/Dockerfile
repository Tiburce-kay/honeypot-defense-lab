# Serveur de défense : reproduit la VM « Server Ubuntu » (Ubuntu Server 24.04 LTS)
# Suricata IPS (NFQUEUE) + iptables/ipset + modules Python + VPN WireGuard + sshd
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Versions figées = celles relevées dans la VM d'origine (dpkg)
ARG SURICATA_VERSION=1:7.0.3-1build3
ARG LIBHTP_VERSION=1:0.5.46-1ubuntu2
ARG IPTABLES_VERSION=1.8.10-3ubuntu2
ARG IPSET_VERSION=7.19-1ubuntu2
ARG FARPD_VERSION=0.2-11.3build3
ARG WG_VERSION=1.0.20210914-1ubuntu4
ARG SCAPY_VERSION=2.5.0+dfsg-2ubuntu1

RUN apt-get update && apt-get install -y --no-install-recommends --allow-downgrades \
        suricata=${SURICATA_VERSION} libhtp2=${LIBHTP_VERSION} \
        iptables=${IPTABLES_VERSION} libxtables12=${IPTABLES_VERSION} \
        libip4tc2=${IPTABLES_VERSION} libip6tc2=${IPTABLES_VERSION} \
        ipset=${IPSET_VERSION} \
        farpd=${FARPD_VERSION} \
        wireguard-tools=${WG_VERSION} \
        python3 python3-scapy=${SCAPY_VERSION} \
        openssh-server iproute2 procps iputils-ping tcpdump supervisor \
    && rm -rf /var/lib/apt/lists/*

# Mêmes chemins que dans la VM : le code d'origine n'a pas à être réécrit
COPY modules/ /home/server/defense_system/modules/
COPY scripts/setup_iptables.sh scripts/vpn_admin.sh /home/server/
COPY suricata/suricata.yaml suricata/threshold.config /etc/suricata/
COPY suricata/defense_system.rules /var/lib/suricata/rules/defense_system.rules
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/supervisord.conf /etc/supervisor/conf.d/defense.conf
COPY docker/healthcheck.sh /usr/local/bin/healthcheck.sh

RUN useradd -m -s /bin/bash server \
    && mkdir -p /home/server/defense_system/logs /home/server/defense_system/signaux \
                /home/server/defense_system/sockets /var/log/suricata /run/sshd \
    && chmod +x /home/server/*.sh /usr/local/bin/*.sh \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && rm -f /etc/ssh/ssh_host_*

HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=10 \
    CMD /usr/local/bin/healthcheck.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
