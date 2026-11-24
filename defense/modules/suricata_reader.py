#!/usr/bin/env python3
"""
Module 2 - Lecture des alertes Suricata.

Surveille le fichier eve.json de Suricata en temps reel.
Transmet les alertes de scan au module de consolidation
via socket Unix.

Une seule detection par IP toutes les 2 secondes.

Auteur  : [Ton nom]
Date    : 2026
Version : 3.0
"""

import os
import json
import socket
import logging
import ipaddress
import time
from datetime import datetime


# ---------------------------------------------------------------------------
# Constantes de configuration
# ---------------------------------------------------------------------------

BASE_DIR      = "/home/server/defense_system"
LOG_DIR       = os.path.join(BASE_DIR, "logs")
LOG_FILE      = os.path.join(LOG_DIR, "suricata_reader.log")
SOCKET_PATH   = os.path.join(BASE_DIR, "sockets", "consolidation.sock")

EVE_FILE      = "/var/log/suricata/eve.json"
IP_SERVEUR    = os.environ.get("DEFENSE_IP", "192.168.10.10")
VLAN_ADMIN    = ipaddress.ip_network("192.168.99.0/24")

# Intervalle de lecture du fichier eve.json (en secondes)
INTERVALLE    = 0.05   # 50ms

# Cooldown : une seule detection par IP par scan (en secondes)
COOLDOWN      = 3.0

# Timestamp de la derniere detection par IP
# { ip_source (str) : timestamp (float) }
derniere_detection: dict = {}


# ---------------------------------------------------------------------------
# Initialisation du systeme de journalisation
# ---------------------------------------------------------------------------

os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("suricata_reader")
logger.setLevel(logging.DEBUG)

_formatter = logging.Formatter(
    fmt="%(asctime)s [%(levelname)-8s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

_fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(_formatter)

_ch = logging.StreamHandler()
_ch.setLevel(logging.INFO)
_ch.setFormatter(_formatter)

logger.addHandler(_fh)
logger.addHandler(_ch)


# ---------------------------------------------------------------------------
# Fonctions utilitaires
# ---------------------------------------------------------------------------

def est_administrateur(ip_src: str) -> bool:
    """
    Verifie si une IP appartient au VLAN d'administration.

    Parametres
    ----------
    ip_src : str

    Retour
    ------
    bool
    """
    try:
        return ipaddress.ip_address(ip_src) in VLAN_ADMIN
    except ValueError:
        return False


def est_alerte_scan(evenement: dict) -> bool:
    """
    Verifie si un evenement Suricata est une alerte de scan reseau.

    Parametres
    ----------
    evenement : dict

    Retour
    ------
    bool
    """
    if evenement.get("event_type") != "alert":
        return False
    signature = evenement.get("alert", {}).get("signature", "").upper()
    return "SCAN" in signature


def en_cooldown(ip_src: str) -> bool:
    """
    Verifie si une IP est en periode de cooldown.

    Parametres
    ----------
    ip_src : str

    Retour
    ------
    bool
    """
    if ip_src not in derniere_detection:
        return False
    return time.time() - derniere_detection[ip_src] < COOLDOWN


# ---------------------------------------------------------------------------
# Communication socket
# ---------------------------------------------------------------------------

def envoyer_au_consolidateur(ip_src: str, type_scan: str,
                              proto: str, admin: bool) -> None:
    """
    Envoie la detection au module de consolidation via socket Unix.
    Latence < 1ms.

    Parametres
    ----------
    ip_src    : str
    type_scan : str
    proto     : str
    admin     : bool
    """
    detection = {
        "horodatage" : datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "ip_source"  : ip_src,
        "type_scan"  : type_scan,
        "protocole"  : proto,
        "est_admin"  : admin,
        "source"     : "suricata"
    }

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.sendto(json.dumps(detection).encode(), SOCKET_PATH)
        sock.close()
        logger.debug(f"Detection envoyee au consolidateur : {ip_src}")

    except FileNotFoundError:
        logger.error("Socket consolidateur introuvable — consolidateur demarre ?")
    except OSError as erreur:
        logger.error(f"Echec envoi socket : {erreur}")


# ---------------------------------------------------------------------------
# Fonctions principales
# ---------------------------------------------------------------------------

def traiter_evenement(evenement: dict) -> None:
    """
    Traite un evenement Suricata.
    Envoie au consolidateur si c'est un scan non en cooldown.

    Parametres
    ----------
    evenement : dict
    """
    if not est_alerte_scan(evenement):
        return

    ip_src = evenement.get("src_ip", "")

    if not ip_src:
        return

    # Ignorer les paquets emis par le serveur lui-meme
    if ip_src == IP_SERVEUR:
        return

    # Ignorer si IP en cooldown
    if en_cooldown(ip_src):
        return

    proto     = evenement.get("proto", "AUTRE")
    type_scan = evenement.get("alert", {}).get("signature", "Scan detecte")
    admin     = est_administrateur(ip_src)
    statut    = "SCAN AUTORISE" if admin else "POTENTIEL ATTAQUANT"
    separateur = "-" * 55

    message = (
        f"\n{separateur}\n"
        f"STATUT     : {statut}\n"
        f"IP source  : {ip_src}\n"
        f"Type scan  : {type_scan}\n"
        f"Protocole  : {proto}\n"
        f"Heure      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{separateur}"
    )

    if admin:
        logger.info(message)
    else:
        logger.warning(message)

    # Marquer le timestamp de cette detection
    derniere_detection[ip_src] = time.time()

    # Envoyer au consolidateur
    envoyer_au_consolidateur(ip_src, type_scan, proto, admin)


def surveiller_eve(chemin: str) -> None:
    """
    Surveille le fichier eve.json de Suricata en temps reel.
    Lit uniquement les nouvelles lignes ajoutees.

    Parametres
    ----------
    chemin : str
    """
    logger.info("=" * 55)
    logger.info("Module 2 - Lecture des alertes Suricata")
    logger.info("=" * 55)
    logger.info(f"Fichier Eve  : {chemin}")
    logger.info(f"Socket       : {SOCKET_PATH}")
    logger.info(f"VLAN Admin   : {VLAN_ADMIN}")
    logger.info(f"Cooldown     : {COOLDOWN}s par IP")
    logger.info("=" * 55)

    with open(chemin, "r", encoding="utf-8") as f:
        # Se positionner a la fin — ignorer les anciens evenements
        f.seek(0, 2)

        while True:
            ligne = f.readline()

            if not ligne:
                time.sleep(INTERVALLE)
                continue

            ligne = ligne.strip()

            if not ligne:
                continue

            try:
                evenement = json.loads(ligne)
                traiter_evenement(evenement)
            except json.JSONDecodeError:
                pass


def demarrer() -> None:
    """
    Point d'entree principal du module.
    Attend que eve.json soit disponible puis lance la surveillance.
    """
    logger.info("Demarrage du module 2...")

    while not os.path.exists(EVE_FILE):
        logger.warning(f"{EVE_FILE} introuvable. Tentative dans 5s...")
        time.sleep(5)

    surveiller_eve(EVE_FILE)


# ---------------------------------------------------------------------------
# Point d'entree
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    demarrer()
