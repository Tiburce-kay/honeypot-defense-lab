# Lab « détection et leurrage de scans réseau » — commandes usuelles
.DEFAULT_GOAL := help
DC := docker compose

help: ## Affiche cette aide
	@grep -hE '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-10s %s\n", $$1, $$2}'

up: ## Construit et démarre tout le lab
	$(DC) up -d --build --wait
	@echo "Lab prêt. Tableau de bord : http://localhost:9443 (make password) — démo : make demo"

demo: ## Rejoue les expériences (scan, piégeage, capture, VPN)
	@bash scripts/demo.sh

password: ## Affiche les identifiants du tableau de bord
	@echo "utilisateur : admin"; printf "mot de passe : "; $(DC) exec -T dashboard cat /lab-secrets/dashboard_password

ps: ## État des conteneurs
	$(DC) ps

logs: ## Journaux en direct du serveur de défense
	$(DC) logs -f defense

kali: ## Ouvre un shell sur le poste attaquant (VLAN 40)
	$(DC) exec attacker bash

admin: ## Ouvre un shell sur le poste d'administration (VLAN 99)
	$(DC) exec admin bash

down: ## Arrête le lab (conserve journaux, clés et attaquants piégés)
	$(DC) down

clean: ## Arrête le lab et efface toutes les données (volumes)
	$(DC) down -v

prereqs: ## (Seulement si le serveur ne démarre pas) charge les modules noyau
	sudo modprobe -a nfnetlink_queue xt_NFQUEUE ip_set ip_set_hash_ip xt_set wireguard

.PHONY: help up demo password ps logs kali admin down clean prereqs
