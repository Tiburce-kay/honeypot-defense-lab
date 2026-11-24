# Guide d'installation

Ce guide explique comment installer et lancer le laboratoire sur une machine neuve,
étape par étape. Compter environ **3 Go d'espace disque** et, au premier lancement,
**5 à 10 minutes** de construction.

## 1. Système requis

Le laboratoire s'appuie sur des fonctions du **noyau Linux** : NFQUEUE (Suricata en IPS),
ipset, WireGuard et réseaux macvlan. Il faut donc une machine **Linux** (Ubuntu, Debian,
Kali, Fedora…) ou une machine virtuelle Linux.

> ⚠️ Il ne fonctionne **pas** sur Docker Desktop pour Windows ou macOS : ces modules noyau
> et le mode macvlan ne sont pas disponibles. Sur Windows, utiliser une VM Linux (ou WSL2
> avec un noyau personnalisé n'est pas garanti).

Matériel conseillé : 2 cœurs, 2 Go de RAM libres, 3 Go de disque.

## 2. Installer les dépendances

Sur Ubuntu / Debian / Kali :

```bash
sudo apt update
sudo apt install -y git docker.io docker-compose-v2 make
```

Autoriser l'utilisation de Docker sans `sudo`, puis se reconnecter :

```bash
sudo usermod -aG docker $USER
newgrp docker          # ou : fermer la session et la rouvrir
docker run --rm hello-world   # test : doit afficher un message de bienvenue
```

## 3. Récupérer le dépôt

Dépôt public :

```bash
git clone https://github.com/Tiburce-kay/honeypot-defense-lab.git
cd honeypot-defense-lab
```

(Si le dépôt est encore privé, s'authentifier d'abord avec la CLI GitHub :
`gh auth login` puis `gh repo clone Tiburce-kay/honeypot-defense-lab`.)

## 4. Démarrer le laboratoire

```bash
make up
```

Cette commande construit les images et démarre les 10 conteneurs (routeur, serveur de
défense, Cowrie, Dionaea, tableau de bord, attaquant, administrateur, deux postes et le
relais du tableau de bord). Elle se termine par :

```
Lab prêt. Tableau de bord : http://localhost:9443 (make password) — démo : make demo
```

## 5. Vérifier que tout fonctionne

```bash
make demo
```

La démonstration rejoue les expériences de bout en bout et doit afficher :

```
== Bilan : 9 réussis, 0 échoués ==
```

## 6. Utiliser le laboratoire

| Commande | Effet |
|---|---|
| `make password` | affiche les identifiants du tableau de bord |
| `make kali` | ouvre un terminal sur le poste attaquant (VLAN 40) |
| `make admin` | ouvre un terminal sur le poste d'administration (VLAN 99) |
| `make logs` | journaux du serveur de défense en direct |
| `make ps` | état des conteneurs |

- **Tableau de bord** : http://localhost:9443 (identifiant `admin`, mot de passe via `make password`).
- **Scénario pas à pas** (nmap, hydra, honeypots, rapport) : voir [`EXPERIENCES.md`](EXPERIENCES.md).

> Le mot de passe du tableau de bord est **généré au premier `make up`** et propre à chaque
> machine. Il n'est pas dans le dépôt. `make password` l'affiche à tout moment.

## 7. Arrêter

```bash
make down      # arrête le lab, conserve les données (clés, journaux, attaquants piégés)
make clean     # arrête et efface tout (volumes) : repart de zéro au prochain make up
```

## Dépannage

**Le serveur de défense ne démarre pas / message sur des modules noyau manquants :**

```bash
make prereqs   # charge nfnetlink_queue, ip_set, xt_set, wireguard… (demande sudo)
make up
```

**Le port 9443 est déjà utilisé :** une autre application occupe le port. L'arrêter, ou
modifier le port publié dans `docker-compose.yml` (service `dashboard-proxy`).

**`permission denied` sur Docker :** l'ajout au groupe `docker` (étape 2) n'a pas été pris en
compte ; se déconnecter puis se reconnecter.

**Conseil :** ne pas faire tourner deux copies du dépôt en même temps. Elles partagent le même
nom de projet Docker Compose ; un `make clean` dans l'une efface les volumes de l'autre.
