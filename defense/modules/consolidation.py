#!/usr/bin/env python3
"""
Module de consolidation.

Recoit les detections de Scapy (passif) et Suricata (actif) via socket Unix.

Logique de decision :
  - source "suricata"      → decision immediate (Suricata a deja DROP)
  - source "scapy_passif"  → journalisation uniquement, pas de decision
    (Suricata a deja agi ; Scapy confirme juste ce que Suricata a fait)

Une alerte consolidee par IP toutes les 60 secondes.

Auteur  : [Ton nom]
Date    : 2026
Version : 3.0
"""

import os
import sys
import json
import socket
import logging
import threading
import time
from datetime import datetime


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR    = "/home/server/defense_system"
LOG_DIR     = os.path.join(BASE_DIR, "logs")
LOG_FILE    = os.path.join(LOG_DIR, "consolidation.log")
SIGNAL_DIR  = os.path.join(BASE_DIR, "signaux")
SIGNAL_FILE = os.path.join(SIGNAL_DIR, "signal.json")
SOCKET_DIR  = os.path.join(BASE_DIR, "sockets")
SOCKET_PATH = os.path.join(SOCKET_DIR, "consolidation.sock")

sys.path.insert(0, BASE_DIR + "/modules")

COOLDOWN_IP = 60.0  # secondes entre deux alertes pour la meme IP


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

os.makedirs(LOG_DIR,    exist_ok=True)
os.makedirs(SIGNAL_DIR, exist_ok=True)
os.makedirs(SOCKET_DIR, exist_ok=True)

logger = logging.getLogger("consolidation")
logger.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s",
                        "%Y-%m-%d %H:%M:%S")
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setLevel(logging.DEBUG); fh.setFormatter(fmt)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO);  ch.setFormatter(fmt)
logger.addHandler(fh); logger.addHandler(ch)


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------

ips_traitees: dict = {}   # { ip : timestamp }
verrou = threading.Lock()


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def en_cooldown(ip: str) -> bool:
    if ip not in ips_traitees:
        return False
    return time.time() - ips_traitees[ip] < COOLDOWN_IP


def ecrire_signal(alerte: dict) -> None:
    try:
        if os.path.exists(SIGNAL_FILE):
            with open(SIGNAL_FILE, "r", encoding="utf-8") as f:
                contenu = f.read().strip()
                signaux = json.loads(contenu) if contenu else []
        else:
            signaux = []
        signaux.append(alerte)
        tmp = SIGNAL_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(signaux, f, indent=4, ensure_ascii=False)
        os.replace(tmp, SIGNAL_FILE)
    except (OSError, json.JSONDecodeError) as e:
        logger.error(f"Echec ecriture signal : {e}")


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

def declencher_decision(detection: dict) -> None:
    """
    Appelle decision.py pour appliquer la redirection DNAT.
    Suricata a deja DROP le paquet ; decision.py pose la regle
    pour les connexions FUTURES de la meme IP.
    """
    ip_src = detection["ip_source"]

    alerte = {
        "horodatage"        : datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "ip_source"         : ip_src,
        "est_admin"         : detection["est_admin"],
        "type_scan"         : detection["type_scan"],
        "protocole"         : detection["protocole"],
        "confirme_suricata" : True,
        "confirme_scapy"    : False,
        "confirme"          : True,
    }

    sep = "=" * 55
    logger.warning(
        f"\n{sep}\nALERTE CONSOLIDEE\n"
        f"IP source : {ip_src}\n"
        f"Type      : {alerte['type_scan']}\n"
        f"Source    : Suricata IPS (decisif)\n"
        f"Heure     : {alerte['horodatage']}\n"
        f"{sep}"
    )

    ecrire_signal(alerte)
    ips_traitees[ip_src] = time.time()

    try:
        from decision import traiter_alerte
        threading.Thread(
            target=traiter_alerte, args=(alerte,), daemon=True
        ).start()
    except ImportError as e:
        logger.error(f"Module decision introuvable : {e}")


def recevoir_detection(detection: dict) -> None:
    ip_src = detection.get("ip_source", "")
    source = detection.get("source", "")

    if not ip_src:
        return

    if en_cooldown(ip_src):
        logger.debug(f"IP en cooldown : {ip_src}")
        return

    # Scapy passif : juste journaliser, pas de decision
    if source == "scapy_passif":
        logger.info(
            f"Scapy passif : {ip_src} — "
            f"{detection.get('type_scan','?')} — "
            f"Suricata a deja agi"
        )
        return

    # Suricata : decideur principal
    if source == "suricata":
        with verrou:
            if en_cooldown(ip_src):
                return
        declencher_decision(detection)
        return

    logger.warning(f"Source inconnue ignoree : {source}")


def demarrer_serveur() -> None:
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o777)

    logger.info("=" * 55)
    logger.info("Module Consolidation v3.0")
    logger.info("Decideur : Suricata uniquement")
    logger.info("=" * 55)
    logger.info(f"Socket    : {SOCKET_PATH}")
    logger.info(f"Signaux   : {SIGNAL_FILE}")
    logger.info(f"Cooldown  : {COOLDOWN_IP}s par IP")
    logger.info("=" * 55)

    while True:
        try:
            donnees, _ = sock.recvfrom(4096)
            detection  = json.loads(donnees.decode())
            recevoir_detection(detection)
        except json.JSONDecodeError as e:
            logger.error(f"JSON invalide : {e}")
        except OSError as e:
            logger.error(f"Erreur socket : {e}")


if __name__ == "__main__":
    demarrer_serveur()
