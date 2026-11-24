# Protocole expérimental

Évaluation défensive du dispositif en laboratoire isolé. On lance des reconnaissances et des
tentatives d'accès contre l'infrastructure, et on mesure que la défense les **détecte, les
détourne vers les leurres et les documente**, sans jamais exposer les ressources réelles.

Ce protocole reproduit les expériences décrites dans le travail de recherche à l'origine du
projet. Il est exécutable de bout en bout, et son automatisation complète se trouve dans
[`scripts/demo.sh`](../scripts/demo.sh).

Toutes les actions « attaquant » se lancent depuis le poste Kali (`make kali`). Les listes de
mots de passe (`passwords.txt`, `userlist.txt`, `passlist.txt`) sont déjà dans `/root`.

```bash
make up        # démarrer le lab
make kali      # ouvrir le poste attaquant (VLAN 40) dans un terminal
make admin     # ouvrir le poste administrateur (VLAN 99) dans un autre
```

Tableau de bord à projeter : **http://localhost:9443** (`make password` pour les identifiants).

---

## Étape 0 — Vérification avant démo

Sur le serveur de défense (ou via `make logs`) :

```bash
# Repartir d'un état neuf
docker compose exec defense ipset flush ATTAQUANTS
docker compose exec defense supervisorctl restart consolidation
# Tous les services doivent être actifs
docker compose exec dashboard python3 -c "import sys;sys.path.insert(0,'/home/server/dashboard');import app,json;print(json.dumps(app.get_services_status(),indent=2))"
```

## Étape 1 — Scan global des deux sous-réseaux

Depuis **Kali** :

```bash
nmap -sS -sV 192.168.10,20.0/24
```

→ Suricata détecte le balayage et inscrit l'attaquant dans l'ipset `ATTAQUANTS`.
À montrer sur le dashboard (vue IDS/IPS) et par :

```bash
docker compose exec defense ipset list ATTAQUANTS
```

## Étape 2 — Attaque sur le serveur de défense

Depuis **Kali** :

```bash
nmap -sV 192.168.10.10
hydra -l root -P passwords.txt -t 4 -f -V ssh://192.168.10.10
ssh root@192.168.10.10           # mot de passe trouvé par hydra : root
whoami
hostname                          # -> srv-prod-01 : c'est le leurre Cowrie
ls -al
cat /etc/passwd                   # NB : sans « | head », non géré par le shell émulé
exit
```

Depuis **Administrateur** (VLAN 99), pour montrer l'exemption :

```bash
ssh server@192.168.10.10
hostname                          # -> server : le VRAI serveur, jamais redirigé
```

## Étape 3 — Attaque sur le serveur applicatif

Depuis **Kali** :

```bash
hydra -l root -P passwords.txt -t 4 -f -V ssh://192.168.20.20
ssh root@192.168.20.20            # -> srv-prod-01 : Cowrie également
```

## Étape 4 — Capture d'une charge sur le honeypot (Dionaea)

Depuis **Kali** :

```bash
nmap -sV 192.168.10.50
cd /tmp
echo '#!/bin/bash'            >  backdoor.sh
echo 'echo "payload de test"' >> backdoor.sh
hydra -L userlist.txt -P passlist.txt -t 16 -f -V ftp://192.168.10.50
ftp ftpuser@192.168.10.50         # Dionaea accepte n'importe quel identifiant
# dans l'invite ftp :
#   put backdoor.sh malware_capture_test4.exe
#   ls
#   quit
```

→ Le fichier est capturé et son empreinte SHA-256 calculée :

```bash
docker compose exec dionaea sh -c 'ls -la var/lib/dionaea/ftp/root/; sha256sum var/lib/dionaea/ftp/root/malware_capture_test4.exe'
```

## Étape 5 — Vue d'ensemble et rapport d'incident

Sur le **tableau de bord** (http://localhost:9443) :

- parcourir les 6 vues : vue d'ensemble, IDS/IPS, honeypots, attaquants, infrastructure, journaux ;
- générer le **rapport d'incident PDF** sur la période de la démonstration (champs début/fin),
  qui récapitule alertes, sessions piégées, fichiers capturés et leurs empreintes SHA-256.

---

### Rappel

Ce scénario est conçu pour un **laboratoire isolé**. `hydra` et les scans ne visent que les
adresses du lab (`192.168.10.0/24`, `192.168.20.0/24`). Ne jamais lancer ces outils contre
une infrastructure que l'on n'a pas l'autorisation explicite de tester.
