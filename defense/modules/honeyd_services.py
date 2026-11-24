#!/usr/bin/env python3
"""
Module 4 — Honeyd Services
Simule des services réseau réalistes sur les IPs fictives.
Profils :
  192.168.10.20 → Serveur web Apache/Tomcat
  192.168.10.30 → Serveur mail Postfix
  192.168.10.40 → Serveur Windows SMB/RDP
  192.168.20.20 → Serveur applicatif Python/Node (prod réaliste)
"""

import socket
import threading
import logging
import os
import time

BASE_DIR = "/home/server/defense_system"
LOG_DIR  = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "honeyd.log")

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("honeyd_services")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s", "%Y-%m-%d %H:%M:%S")
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(fmt)
ch = logging.StreamHandler()
ch.setFormatter(fmt)
logger.addHandler(fh)
logger.addHandler(ch)

# ── Banners par service ───────────────────────────────────────

BANNERS = {

    # ── 192.168.10.20 — Serveur Web ──────────────────────────
    ("192.168.10.20", 22): (
        b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
    ),
    ("192.168.10.20", 80): (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.57 (Debian)\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"X-Powered-By: PHP/8.2.7\r\n"
        b"Connection: close\r\n\r\n"
        b"<html><body><h1>Apache2 Default Page</h1></body></html>\r\n"
    ),
    ("192.168.10.20", 443): (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.57 (Debian)\r\n"
        b"Content-Type: text/html\r\n"
        b"Connection: close\r\n\r\n"
    ),
    ("192.168.10.20", 8080): (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache-Coyote/1.1\r\n"
        b"Content-Type: text/html;charset=utf-8\r\n"
        b"Connection: close\r\n\r\n"
        b"<html><body><h2>Tomcat 9.0.80</h2></body></html>\r\n"
    ),

    # ── 192.168.10.30 — Serveur Mail ─────────────────────────
    ("192.168.10.30", 22): (
        b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
    ),
    ("192.168.10.30", 21): (
        b"220 ProFTPD 1.3.8 Server (Debian) [::ffff:192.168.10.30]\r\n"
    ),
    ("192.168.10.30", 25): (
        b"220 mail.srv-prod-01.local ESMTP Postfix (Debian/GNU)\r\n"
    ),
    ("192.168.10.30", 110): (
        b"+OK Dovecot ready.\r\n"
    ),
    ("192.168.10.30", 143): (
        b"* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN] Dovecot ready.\r\n"
    ),

    # ── 192.168.10.40 — Serveur Windows ──────────────────────
    ("192.168.10.40", 135): (
        b"\x05\x00\x0c\x03\x10\x00\x00\x00\x44\x00\x00\x00"
    ),
    ("192.168.10.40", 139): (
        b"\x82\x00\x00\x00"
    ),
    ("192.168.10.40", 445): (
        b"\x00\x00\x00\x00"
    ),
    ("192.168.10.40", 3389): (
        b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x00\x00"
    ),

    # ── 192.168.20.20 — Serveur applicatif PROD réaliste ─────
    # Profil : backend Python/Node avec reverse proxy Nginx
    # Ports exposés : 22 (SSH admin), 80 (redirect HTTPS),
    #                 443 (app principale), 8443 (API REST)
    # PAS de 8080 Tomcat, PAS de PostgreSQL exposé, PAS de Redis exposé
    # → réaliste pour un serveur appli sécurisé en prod

    ("192.168.20.20", 22): (
        b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n"
    ),
    ("192.168.20.20", 80): (
        b"HTTP/1.1 301 Moved Permanently\r\n"
        b"Server: nginx/1.24.0 (Ubuntu)\r\n"
        b"Location: https://192.168.20.20/\r\n"
        b"Content-Type: text/html\r\n"
        b"Connection: close\r\n\r\n"
        b"<html><head><title>301 Moved Permanently</title></head>"
        b"<body><h1>301 Moved Permanently</h1></body></html>\r\n"
    ),
    ("192.168.20.20", 443): (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0 (Ubuntu)\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"X-Frame-Options: SAMEORIGIN\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Strict-Transport-Security: max-age=31536000\r\n"
        b"Connection: close\r\n\r\n"
        b"<html><body><h1>Application</h1></body></html>\r\n"
    ),
    ("192.168.20.20", 8443): (
        b"HTTP/1.1 401 Unauthorized\r\n"
        b"Server: nginx/1.24.0 (Ubuntu)\r\n"
        b"Content-Type: application/json\r\n"
        b"WWW-Authenticate: Bearer\r\n"
        b"Connection: close\r\n\r\n"
        b'{"error":"Unauthorized","message":"Authentication required"}\r\n'
    ),
}

# ── Serveur TCP générique ─────────────────────────────────────

def handle_client(conn, addr, banner):
    try:
        conn.settimeout(5)
        conn.send(banner)
        conn.recv(1024)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def start_listener(ip, port, banner):
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((ip, port))
        srv.listen(5)
        logger.info(f"Écoute sur {ip}:{port}")
        while True:
            try:
                conn, addr = srv.accept()
                logger.info(f"Connexion honeyd {ip}:{port} ← {addr[0]}:{addr[1]}")
                t = threading.Thread(
                    target=handle_client, args=(conn, addr, banner), daemon=True
                )
                t.start()
            except Exception as e:
                logger.error(f"Erreur accept {ip}:{port} : {e}")
                time.sleep(1)
    except Exception as e:
        logger.error(f"Impossible d'écouter sur {ip}:{port} : {e}")


def demarrer():
    logger.info("=" * 55)
    logger.info("Module 4 — Honeyd Services (profils réalistes)")
    logger.info("=" * 55)

    threads = []
    for (ip, port), banner in BANNERS.items():
        t = threading.Thread(
            target=start_listener, args=(ip, port, banner), daemon=True
        )
        t.start()
        threads.append(t)
        time.sleep(0.05)

    logger.info(f"{len(BANNERS)} services démarrés")

    for t in threads:
        t.join()


if __name__ == "__main__":
    demarrer()
