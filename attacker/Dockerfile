# Poste attaquant (VLAN 40) — remplace la VM Kali : seuls les outils des essais
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap hydra ftp openssh-client sshpass lftp curl iproute2 iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
# Listes pour la démo de soutenance (hydra)
COPY passwords.txt userlist.txt passlist.txt /root/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
