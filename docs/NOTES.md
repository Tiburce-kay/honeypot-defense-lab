# Notes techniques : de la VM aux conteneurs

Ce document explique comment le laboratoire GNS3/VirtualBox du mémoire a été transformé
en environnement Docker reproductible, et pourquoi chaque choix a été fait.

## 1. Méthode

1. Le disque de la VM « Server Ubuntu » a été monté **en lecture seule** (`qemu-nbd --read-only`)
   pour en extraire le code, les configurations, les unités systemd et la liste des paquets (`dpkg`).
2. Les versions installées ont été relevées et **figées** dans les Dockerfiles.
3. Le code d'origine a été copié tel quel, puis adapté au strict minimum (section 3).
4. Les essais du chapitre 3 du mémoire ont été automatisés dans `scripts/demo.sh`.

## 2. Versions

| Composant | Version | Source |
|---|---|---|
| Ubuntu | 24.04 LTS | image `ubuntu:24.04` |
| Suricata | `1:7.0.3-1build3` | paquet Ubuntu, version de la VM |
| iptables / ipset | `1.8.10-3ubuntu2` / `7.19-1ubuntu2` | idem |
| farpd | `0.2-11.3build3` | idem |
| wireguard-tools | `1.0.20210914-1ubuntu4` | idem |
| Scapy | `2.5.0+dfsg-2ubuntu1` | idem |
| Python | 3.12 | idem |
| Cowrie | `v3.0.3` | tag Git, identique à la VM |
| Dionaea | `0.11.0` | image officielle `dinotools/dionaea` (la VM utilisait une compilation Git `0.11.0-7`) |
| Flask / fpdf2 | 3.0 / 2.8 | versions citées dans le mémoire |

## 3. Adaptations du code d'origine

Toutes les valeurs par défaut restent celles de la VM : le code fonctionne toujours tel quel sur la VM.

| Fichier | Changement | Raison |
|---|---|---|
| `surveillance.py`, `decision.py`, `suricata_reader.py` | interface, IP du serveur et passerelle NAT lus depuis des variables d'environnement | l'interface s'appelle `eth0` dans Docker, `enp0s3` dans la VM |
| `decision.py` | l'ajout de la passerelle NAT à l'ipset devient optionnel | dans le lab Docker, R1 route sans NAT inter-VLAN (voir 5.2) |
| `setup_iptables.sh` | variable `IFACE` ; test de `wg0` sans `systemctl` | pas de systemd dans un conteneur |
| `app.py` (dashboard) | état des services par `pgrep` quand systemd est absent ; clé secrète Flask générée | même raison ; une clé écrite en dur dans le code ne doit pas être publiée |
| `cowrie.cfg` | seules les sections utiles sont conservées | les autres reprennent les valeurs par défaut de Cowrie |

`vpn_admin.sh` n'a pas été modifié.

## 4. De systemd à Docker

Les 8 unités systemd de la VM sont remplacées ainsi, dans le même ordre :

| Unité systemd (VM) | Équivalent Docker |
|---|---|
| `ipset-persistent` + `ipset-save.timer` | `entrypoint.sh` (restauration) + boucle `ipset_save` toutes les 5 min (supervisord) |
| `defense-iptables` | `entrypoint.sh` → `setup_iptables.sh` |
| `wg-quick@wg0` | `entrypoint.sh` → `wg-quick up wg0` (PostUp = `vpn_admin.sh pare-feu-up`) |
| `suricata-ips` | supervisord `suricata -q 0` |
| `defense-modules` | supervisord : consolidation → suricata_reader → surveillance → honeyd_services |
| `cowrie` | conteneur `cowrie` |
| `dionaea` | conteneur `dionaea` |
| `dashboard-soc` | conteneur `dashboard` |

**Une seule pile réseau.** Dans la VM, tout tournait sur la même machine : Cowrie écoutait sur
`:2222` et iptables y redirigeait le trafic localement. Pour garder ce fonctionnement, `cowrie`,
`dionaea` et `dashboard` utilisent `network_mode: service:defense` (même pile réseau) et
`pid: service:defense` (même espace de processus, pour l'état des services).

## 5. Réseau

### 5.1 Pourquoi des réseaux macvlan

Avec des réseaux Docker de type `bridge`, la protection ajoutée par Docker 28 (table `raw` de
l'hôte) jette tout paquet destiné à un conteneur s'il arrive par un autre pont. Un routeur en
conteneur entre plusieurs ponts est donc bloqué. Les réseaux **macvlan sans interface parente**
forment des commutateurs virtuels isolés qui ne passent pas par le pare-feu de l'hôte : c'est
l'équivalent le plus fidèle du commutateur ESW1, et le lab fonctionne sans modifier la
configuration de Docker de l'utilisateur.

Conséquence : on ne peut pas publier de port depuis un réseau macvlan. Le relais
`dashboard-proxy` (socat) rend le tableau de bord joignable sur `http://localhost:9443`. Il se
présente au serveur avec l'adresse `192.168.10.253`, autorisée par l'entrypoint (désactivable
avec `DASHBOARD_FROM_HOST=0`).

### 5.2 Routage par R1

Dans le lab GNS3, le trafic inter-VLAN arrivait sur le serveur avec l'adresse de la passerelle
`192.168.10.254`, d'où la double inscription dans l'ipset (adresse de l'attaquant + passerelle).
Ici, R1 route sans translation : le serveur voit directement l'adresse réelle de l'attaquant.
La double inscription reste disponible (`DEFENSE_GATEWAY_NAT=192.168.10.254`) mais n'est pas
nécessaire.

### 5.3 Modules noyau

Suricata (NFQUEUE), ipset et WireGuard utilisent des modules du noyau de l'hôte. Ils sont
normalement chargés automatiquement à la première utilisation. Si le serveur de défense ne
démarre pas, `make prereqs` les charge avec `sudo modprobe`.

## 6. Comportements connus (identiques à la VM)

- `honeyd_services.py` signale `Address already in use` sur `192.168.20.20:22` : le vrai sshd
  écoute déjà sur `0.0.0.0:22`. Sans conséquence, puisque le port 22 de ce leurre est redirigé
  vers Cowrie par iptables. Le même message apparaît dans les journaux de la VM.
- Après détection, `nmap` voit presque tous les ports « ouverts » : c'est voulu, toutes les
  connexions de l'attaquant aboutissent sur Cowrie.

## 7. Persistance

`setup_iptables.sh` détruit puis recrée les ipsets à chaque exécution. Pour que les attaquants
sauvegardés survivent à un redémarrage, l'entrypoint restaure l'ipset **après**
`setup_iptables.sh`. Vérification : `docker compose restart defense`, puis
`docker compose exec defense ipset list ATTAQUANTS`.
