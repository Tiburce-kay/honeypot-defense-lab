#!/usr/bin/env python3
"""
Test rapide du module de surveillance.
Simule des paquets sans avoir besoin du réseau.
"""

from scapy.all import IP, TCP, Ether
from surveillance import analyser_paquet, connexions
import logging

logging.basicConfig(level=logging.INFO)

print("=== TEST MODULE SURVEILLANCE ===\n")

# Simuler un scan de ports depuis Kali Attaquant
ip_attaquant = "192.168.40.2"
ip_serveur   = "192.168.10.10"

print(f"Simulation scan depuis {ip_attaquant}...\n")

# Envoyer 15 paquets vers des ports différents
for port in range(20, 35):
    paquet = (
        IP(src=ip_attaquant, dst=ip_serveur) /
        TCP(dport=port, flags="S")
    )
    analyser_paquet(paquet)

print(f"\nRésultat tracker : {connexions.get(ip_attaquant, {})}")
print("\n✅ Test terminé")
