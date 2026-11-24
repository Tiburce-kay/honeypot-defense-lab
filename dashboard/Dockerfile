# Tableau de bord SOC (Flask + SocketIO) — module 7
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends ipset sudo procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Même chemin que dans la VM
COPY app.py /home/server/dashboard/app.py
COPY templates/ /home/server/dashboard/templates/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

WORKDIR /home/server/dashboard
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
