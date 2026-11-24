# Honeypot SSH Cowrie — même version que la VM (git tag v3.0.3, Python 3.12)
FROM python:3.12-slim-bookworm

ARG COWRIE_VERSION=v3.0.3

RUN apt-get update && apt-get install -y --no-install-recommends git libssl-dev libffi-dev build-essential \
    && useradd -m -s /bin/bash cowrie \
    && su cowrie -c "git clone --depth 1 --branch ${COWRIE_VERSION} https://github.com/cowrie/cowrie /home/cowrie/cowrie" \
    && su cowrie -c "python3 -m venv /home/cowrie/cowrie/cowrie-env \
         && /home/cowrie/cowrie/cowrie-env/bin/pip install --no-cache-dir --upgrade pip \
         && /home/cowrie/cowrie/cowrie-env/bin/pip install --no-cache-dir -e /home/cowrie/cowrie \
         && mkdir -p /home/cowrie/cowrie/var/log/cowrie /home/cowrie/cowrie/var/lib/cowrie/downloads /home/cowrie/cowrie/var/lib/cowrie/tty" \
    && apt-get purge -y build-essential git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

COPY --chown=cowrie:cowrie cowrie.cfg userdb.txt /home/cowrie/cowrie/etc/

USER cowrie
WORKDIR /home/cowrie/cowrie
ENV PATH=/home/cowrie/cowrie/cowrie-env/bin:$PATH
# Premier plan (équivalent de « cowrie start » de l'unité systemd cowrie.service)
CMD ["twistd", "-n", "--umask=0022", "--pidfile=", "-l", "-", "cowrie"]
