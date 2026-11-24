#!/usr/bin/env python3
"""
Module 3 — Décision et redirection vers honeypot.

La redirection est gérée par ipset + iptables permanent (setup_iptables.sh).
Ce module ajoute simplement l'IP attaquante dans l'ipset ATTAQUANTS.
La règle DNAT s'applique instantanément — pas besoin de poser
des règles iptables individuelles à chaque détection.

Avantage : O(1) en temps, pas de règles iptables qui s'accumulent.
"""

import os
import logging
import ipaddress
import subprocess
from datetime import datetime

BASE_DIR      = "/home/server/defense_system"
LOG_DIR       = os.path.join(BASE_DIR, "logs")
LOG_FILE      = os.path.join(LOG_DIR, "decision.log")

VLAN_ADMIN    = ipaddress.ip_network("192.168.99.0/24")
IP_HONEYPOT   = os.environ.get("DEFENSE_IP", "192.168.10.10")
PORT_HONEYPOT = 2222
IPSET_NAME    = "ATTAQUANTS"
# Valeurs par defaut = celles de la VM d'origine.
# Dans le lab Docker, R1 route sans NAT inter-VLAN : DEFENSE_GATEWAY_NAT est vide
# et l'adresse reelle de l'attaquant arrive directement sur le serveur.
GATEWAY_R1    = os.environ.get("DEFENSE_GATEWAY_NAT", "192.168.10.254")  # IP NAT inter-VLAN (gateway R1)
INTERFACE     = os.environ.get("DEFENSE_IFACE", "enp0s3")
IPS_PROTEGEES = {IP_HONEYPOT, GATEWAY_R1, "127.0.0.1"} - {""}

ips_redirigees: set = set()

os.makedirs(LOG_DIR, exist_ok=True)
logger = logging.getLogger("decision")
logger.setLevel(logging.DEBUG)
fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s", "%Y-%m-%d %H:%M:%S")
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setLevel(logging.DEBUG); fh.setFormatter(fmt)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO);  ch.setFormatter(fmt)
logger.addHandler(fh); logger.addHandler(ch)


def est_administrateur(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in VLAN_ADMIN
    except ValueError:
        return False


def appliquer_redirection(ip_src: str) -> None:
    """
    Ajoute l'IP dans l'ipset ATTAQUANTS.
    Ajoute aussi la gateway R1 (192.168.10.254) car c'est l'IP
    qui arrive physiquement sur le serveur après NAT inter-VLAN.
    """
    # Vérifier dans l'ipset réel — persistant entre les redémarrages
    check = subprocess.run(
        ["ipset", "test", IPSET_NAME, ip_src],
        capture_output=True
    )
    if check.returncode == 0:
        logger.debug(f"IP déjà dans ipset (persistant) : {ip_src}")
        return

    sep = "-" * 55
    try:
        # 1. Ajouter l'IP détectée par Suricata
        result = subprocess.run(
            ["ipset", "add", IPSET_NAME, ip_src, "timeout", "3600"],
            capture_output=True, text=True
        )
        if result.returncode != 0 and "already added" not in result.stderr:
            logger.error(f"Échec ipset add {ip_src} : {result.stderr.strip()}")
            return

        # 2. Ajouter aussi la gateway R1 (IP après NAT inter-VLAN)
        if GATEWAY_R1:
            gw_result = subprocess.run(
                ["ipset", "add", IPSET_NAME, GATEWAY_R1, "timeout", "3600"],
                capture_output=True, text=True
            )
            if gw_result.returncode == 0:
                logger.info(f"Gateway R1 {GATEWAY_R1} ajoutée à l'ipset")
            elif "already added" in gw_result.stderr:
                logger.debug(f"Gateway R1 {GATEWAY_R1} déjà dans l'ipset")
            else:
                logger.error(f"Échec ipset add gateway : {gw_result.stderr.strip()}")

        # 3. Bloquer RST sortants vers les deux IPs
        for ip in [i for i in (ip_src, GATEWAY_R1) if i]:
            subprocess.run([
                "iptables", "-A", "BLOCK_RST_OUT",
                "-d", ip, "-p", "tcp",
                "--tcp-flags", "RST", "RST", "-j", "DROP"
            ], check=False)

        # 4. SNAT retour Cowrie
        check = subprocess.run([
            "iptables", "-t", "nat", "-C", "POSTROUTING",
            "-p", "tcp", "--sport", "2222",
            "-o", INTERFACE, "-j", "SNAT", "--to-source", IP_HONEYPOT
        ], capture_output=True)
        if check.returncode != 0:
            subprocess.run([
                "iptables", "-t", "nat", "-A", "POSTROUTING",
                "-p", "tcp", "--sport", "2222",
                "-o", INTERFACE, "-j", "SNAT", "--to-source", IP_HONEYPOT
            ], check=False)

        # ips_redirigees.add(ip_src)  # Désactivé — on utilise l'ipset réel
        logger.warning(
            f"\n{sep}\n"
            f"REDIRECTION ACTIVÉE\n"
            f"IP Suricata  : {ip_src}\n"
            f"IP NAT (R1)  : {GATEWAY_R1 or '(aucune)'}\n"
            f"Destination  : {IP_HONEYPOT}:{PORT_HONEYPOT}\n"
            f"Méthode      : ipset ATTAQUANTS (instantané)\n"
            f"Expiration   : 3600s\n"
            f"Heure        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"{sep}"
        )

    except subprocess.CalledProcessError as e:
        err = e.stderr.decode().strip() if e.stderr else str(e)
        logger.error(f"Échec redirection : {err}")


def traiter_alerte(alerte: dict) -> None:
    ip_src    = alerte.get("ip_source", "")
    est_admin = alerte.get("est_admin", False)
    type_scan = alerte.get("type_scan", "inconnu")
    sep       = "-" * 55

    if not ip_src:
        logger.error("Alerte sans IP source — ignorée")
        return

    # Ne jamais rediriger le serveur lui-même ni la gateway R1
    if ip_src in IPS_PROTEGEES:
        logger.debug(f"IP protégée ignorée : {ip_src}")
        return

    if est_admin:
        logger.info(
            f"\n{sep}\n"
            f"DÉCISION : AUTORISER\n"
            f"IP       : {ip_src}\n"
            f"Raison   : VLAN Admin\n"
            f"{sep}"
        )
        return

    logger.warning(
        f"\n{sep}\n"
        f"DÉCISION : REDIRIGER\n"
        f"IP       : {ip_src}\n"
        f"Type     : {type_scan}\n"
        f"Heure    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"{sep}"
    )
    appliquer_redirection(ip_src)
