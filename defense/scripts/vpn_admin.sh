#!/bin/bash
# ============================================================================
# vpn_admin.sh — Accès d'administration à distance par WireGuard
#                Architecture hôte-à-hôte (NIST SP 800-77r1, §2.4.3)
#
#   Le tunnel se termine sur le serveur de défense lui-même et NE ROUTE
#   VERS RIEN. Depuis le tunnel, l'administrateur n'atteint que :
#       10.99.0.1:22    -> vrai sshd du serveur
#       10.99.0.1:9443  -> tableau de bord SOC
#   - tout le reste arrivant par wg0 est refusé (chaîne WG-ADMIN) ;
#   - aucun paquet n'est transféré depuis ou vers wg0 (FORWARD, DOCKER-USER) ;
#   - le tunnel échappe à toutes les redirections NAT du dispositif
#     (RETURN en tête de PREROUTING) : l'admin n'est jamais envoyé vers Cowrie ;
#   - le flux chiffré udp/51820 est accepté avant toute mise en file NFQUEUE.
#
#   >>> À LANCER EN ROOT :
#       sudo bash vpn_admin.sh installer
#       sudo bash vpn_admin.sh ajouter <nom> <cle_publique_client>
#       sudo bash vpn_admin.sh retirer <nom>
#       sudo bash vpn_admin.sh etat
#       sudo bash vpn_admin.sh pare-feu-up   (à relancer après toute
#                                             reconstruction des règles iptables)
#   (pare-feu-up / pare-feu-down sont aussi appelés automatiquement par wg-quick)
#
#   Seules des clés PUBLIQUES transitent entre le serveur et le poste
#   distant : chaque clé privée reste sur la machine qui l'a générée.
# ============================================================================
set -euo pipefail

# ---------- Paramètres À ADAPTER ----------
PORTS_ADMIN="22,9443"                    # vrai sshd + tableau de bord SOC
ENDPOINT_PUBLIC="IP_DU_PC_HOTE:51820"    # adresse Wi-Fi/Ethernet du PC hôte (ipconfig)
IP_SERVEUR_LAN="192.168.10.10"           # adresse LAN du serveur de défense
INTERFACE_WAN_R1="GigabitEthernet1/0"    # interface « ip nat outside » de R1

# ---------- Paramètres fixes ----------
WG_IF="wg0"
WG_DIR="/etc/wireguard"
WG_CONF="$WG_DIR/$WG_IF.conf"
CLE_PRIVEE="$WG_DIR/privatekey"
CLE_PUBLIQUE="$WG_DIR/publickey"
WG_PORT="51820"
RESEAU_TUNNEL="10.99.0"                  # /24 réservé au tunnel d'administration
IP_SERVEUR_TUNNEL="$RESEAU_TUNNEL.1"
CHAINE="WG-ADMIN"
GARDE="GARDE-9443"                       # garde du tableau de bord
PORT_TABLEAU="9443"
DROPIN_DIR="/etc/systemd/system/wg-quick@$WG_IF.service.d"
SCRIPT="$(readlink -f "$0")"

# ---------- Utilitaires ----------
erreur() { echo "ERREUR : $*" >&2; exit 1; }

verifier_root() {
    [ "$(id -u)" -eq 0 ] || erreur "à lancer en root :  sudo bash $(basename "$0") $*"
}

verifier_installe() {
    [ -f "$WG_CONF" ] || erreur "$WG_CONF absent — lance d'abord :  sudo bash $(basename "$0") installer"
}

verifier_endpoint() {
    case "$ENDPOINT_PUBLIC" in
        IP_DU_PC_HOTE*) echo "  ! ENDPOINT_PUBLIC n'est pas renseigné en tête du script :"
                        echo "    remplace IP_DU_PC_HOTE par l'adresse du PC hôte (ipconfig)." ;;
    esac
}

usage() {
    cat <<EOF
Usage (en root) :
  sudo bash $(basename "$0") installer
  sudo bash $(basename "$0") ajouter <nom> <cle_publique_client>
  sudo bash $(basename "$0") retirer <nom>
  sudo bash $(basename "$0") etat
  sudo bash $(basename "$0") pare-feu-up
EOF
    exit 1
}

# Retire toutes les occurrences d'une règle (table, chaîne, spécification).
retirer_regle() {
    local table="$1" chaine="$2"
    shift 2
    while iptables -t "$table" -D "$chaine" "$@" 2>/dev/null; do :; done
}

# Applique wg0.conf à chaud, sans couper les sessions déjà ouvertes.
appliquer() {
    if ip link show "$WG_IF" >/dev/null 2>&1; then
        wg syncconf "$WG_IF" <(wg-quick strip "$WG_IF")
        echo "  Configuration appliquée à chaud (sessions en cours conservées)."
    else
        echo "  Interface $WG_IF inactive : la modification sera prise en compte au prochain démarrage."
    fi
}

afficher_modele_client() {        # $1 = IP du poste distant dans le tunnel
    verifier_endpoint
    cat <<EOF

  ---- Configuration à saisir dans l'application WireGuard (poste distant) ----
  [Interface]
  PrivateKey = (laisser celle générée par l'application, ne pas la modifier)
  Address    = $1/32

  [Peer]
  PublicKey  = $(cat "$CLE_PUBLIQUE")
  Endpoint   = $ENDPOINT_PUBLIC
  AllowedIPs = $IP_SERVEUR_TUNNEL/32
  PersistentKeepalive = 25
  ---------------------------------------------------------------------------
  Une fois le tunnel activé :  ssh <utilisateur>@$IP_SERVEUR_TUNNEL
                               http://$IP_SERVEUR_TUNNEL:9443
EOF
}

# ---------- Garde du tableau de bord ----------
# Le tableau de bord ecoute sur 0.0.0.0 (necessaire pour joindre 10.99.0.1).
# Cette garde le rend injoignable sur les autres adresses portees par le serveur
# (leurres Honeyd). Elle est independante du tunnel : elle reste si wg0 s'arrete.
garde_tableau() {
    iptables -N "$GARDE" 2>/dev/null || iptables -F "$GARDE"
    iptables -A "$GARDE" -d "$IP_SERVEUR_LAN" -j RETURN
    iptables -A "$GARDE" -d "$IP_SERVEUR_TUNNEL" -j RETURN
    iptables -A "$GARDE" -d 127.0.0.0/8 -j RETURN
    iptables -A "$GARDE" -j DROP
    retirer_regle filter INPUT -p tcp --dport "$PORT_TABLEAU" -j "$GARDE"
    iptables -I INPUT 1 -p tcp --dport "$PORT_TABLEAU" -j "$GARDE"
}

# ---------- Pare-feu du tunnel ----------
# Chaque règle est retirée puis réinsérée en 1re position : le tunnel reste
# prioritaire même si un script du dispositif a ajouté ses règles entre-temps.
pare_feu_up() {
    local sens

    # 1) NAT : le tunnel échappe à toutes les redirections du dispositif
    #    (DNAT du SSH vers Cowrie, DNAT des attaquants, y compris en UDP).
    retirer_regle nat PREROUTING -p udp --dport "$WG_PORT" -j RETURN
    retirer_regle nat PREROUTING -i "$WG_IF" -j RETURN
    iptables -t nat -I PREROUTING 1 -p udp --dport "$WG_PORT" -j RETURN
    iptables -t nat -I PREROUTING 1 -i "$WG_IF" -j RETURN

    # 2) INPUT : le flux chiffré est accepté avant toute file NFQUEUE ;
    #    depuis le tunnel, seuls SSH et le tableau de bord sont joignables.
    iptables -N "$CHAINE" 2>/dev/null || iptables -F "$CHAINE"
    iptables -A "$CHAINE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A "$CHAINE" -p tcp -m multiport --dports "$PORTS_ADMIN" -j ACCEPT
    iptables -A "$CHAINE" -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A "$CHAINE" -j DROP
    retirer_regle filter INPUT -i "$WG_IF" -j "$CHAINE"
    retirer_regle filter INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    iptables -I INPUT 1 -i "$WG_IF" -j "$CHAINE"
    iptables -I INPUT 1 -p udp --dport "$WG_PORT" -j ACCEPT

    garde_tableau

    # 3) FORWARD : le tunnel ne route vers rien (ni VLAN, ni conteneurs).
    #    Règles posées en tête de FORWARD et dans DOCKER-USER (évaluée avant
    #    les règles de Docker, que Docker ne modifie jamais).
    iptables -N DOCKER-USER 2>/dev/null || true
    iptables -C FORWARD -j DOCKER-USER 2>/dev/null \
        || iptables -I FORWARD 1 -j DOCKER-USER
    for sens in -i -o; do
        retirer_regle filter DOCKER-USER "$sens" "$WG_IF" -j DROP
        iptables -I DOCKER-USER 1 "$sens" "$WG_IF" -j DROP
        retirer_regle filter FORWARD "$sens" "$WG_IF" -j DROP
        iptables -I FORWARD 1 "$sens" "$WG_IF" -j DROP
    done
}

pare_feu_down() {
    local sens
    retirer_regle nat PREROUTING -p udp --dport "$WG_PORT" -j RETURN
    retirer_regle nat PREROUTING -i "$WG_IF" -j RETURN
    retirer_regle filter INPUT -i "$WG_IF" -j "$CHAINE"
    retirer_regle filter INPUT -p udp --dport "$WG_PORT" -j ACCEPT
    iptables -F "$CHAINE" 2>/dev/null || true
    iptables -X "$CHAINE" 2>/dev/null || true
    for sens in -i -o; do
        retirer_regle filter DOCKER-USER "$sens" "$WG_IF" -j DROP
        retirer_regle filter FORWARD "$sens" "$WG_IF" -j DROP
    done
}

# ---------- Installation ----------
installer() {
    verifier_root installer

    echo "==================================================================="
    echo " INSTALLATION DE L'ACCÈS D'ADMINISTRATION À DISTANCE (WireGuard)"
    echo "==================================================================="
    echo "  Note : wg-quick appellera ce script à l'emplacement $SCRIPT"
    echo "         ne le déplace plus après l'installation."
    verifier_endpoint

    echo "[1/5] Paquet wireguard-tools..."
    if ! command -v wg >/dev/null 2>&1; then
        apt-get update -qq \
            || echo "      ! apt-get update a signalé des erreurs, installation tentée quand même"
        apt-get install -y -qq wireguard-tools \
            || erreur "installation de wireguard-tools impossible (accès Internet du serveur ?)"
    fi
    echo "      ok $(wg --version 2>/dev/null | head -n1)"
    modprobe wireguard 2>/dev/null || erreur "module noyau wireguard indisponible"

    echo "[2/5] Clés du serveur..."
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"
    if [ ! -f "$CLE_PRIVEE" ]; then
        (umask 077; wg genkey > "$CLE_PRIVEE")
        wg pubkey < "$CLE_PRIVEE" > "$CLE_PUBLIQUE"
        echo "      + paire de clés générée"
    else
        [ -f "$CLE_PUBLIQUE" ] || wg pubkey < "$CLE_PRIVEE" > "$CLE_PUBLIQUE"
        echo "      = clés déjà présentes (conservées)"
    fi

    echo "[3/5] $WG_CONF..."
    if [ ! -f "$WG_CONF" ]; then
        (umask 077; cat > "$WG_CONF" <<EOF
# $WG_CONF — généré par vpn_admin.sh (ne pas éditer à la main :
# utiliser  vpn_admin.sh ajouter|retirer)
[Interface]
Address    = $IP_SERVEUR_TUNNEL/24
ListenPort = $WG_PORT
PrivateKey = $(cat "$CLE_PRIVEE")
PostUp     = bash $SCRIPT pare-feu-up
PostDown   = bash $SCRIPT pare-feu-down
EOF
        )
        echo "      + configuration créée"
    else
        echo "      = déjà présente (administrateurs déclarés conservés)"
    fi

    echo "[4/5] Ordre de démarrage systemd..."
    mkdir -p "$DROPIN_DIR"
    cat > "$DROPIN_DIR/ordre-defense.conf" <<EOF
# Généré par vpn_admin.sh — les règles du tunnel doivent être posées APRÈS
# celles du dispositif (iptables, Docker), pour rester en première position.
[Unit]
After=network-online.target docker.service defense-iptables.service
Wants=network-online.target
EOF
    systemctl daemon-reload
    echo "      ok wg-quick@$WG_IF démarre après docker et defense-iptables"

    echo "[5/5] Activation au boot et démarrage..."
    systemctl enable "wg-quick@$WG_IF" >/dev/null 2>&1 \
        || erreur "impossible d'activer wg-quick@$WG_IF au démarrage"
    if systemctl restart "wg-quick@$WG_IF"; then
        echo "      ok wg-quick@$WG_IF actif"
    else
        journalctl -u "wg-quick@$WG_IF" -n 20 --no-pager >&2 || true
        erreur "wg-quick@$WG_IF n'a pas démarré (journal ci-dessus)"
    fi

    echo ""
    echo "==================================================================="
    echo " PRÊT — étapes suivantes"
    echo "==================================================================="
    echo " Clé publique du serveur (à recopier dans le poste distant) :"
    echo "   $(cat "$CLE_PUBLIQUE")"
    echo ""
    echo " Sur R1 (une seule ligne, puis sauvegarde) :"
    echo "   configure terminal"
    echo "   ip nat inside source static udp $IP_SERVEUR_LAN $WG_PORT interface $INTERFACE_WAN_R1 $WG_PORT"
    echo "   end"
    echo "   write memory        (puis Entrée à [confirm])"
    echo ""
    echo " Dans VMware (NAT de VMnet8) : redirection UDP $WG_PORT vers l'IP WAN de R1."
    echo ""
    echo " Puis, avec la clé publique affichée par l'application WireGuard :"
    echo "   sudo bash $(basename "$0") ajouter <nom> <cle_publique_client>"
    echo "==================================================================="
}

# ---------- Gestion des administrateurs ----------
prochaine_ip() {
    local n
    for n in $(seq 2 254); do
        grep -qF "AllowedIPs = $RESEAU_TUNNEL.$n/32" "$WG_CONF" || { echo "$RESEAU_TUNNEL.$n"; return 0; }
    done
    erreur "plus aucune adresse libre dans $RESEAU_TUNNEL.0/24"
}

ajouter() {                       # $1 = nom, $2 = clé publique du client
    verifier_root ajouter
    verifier_installe
    local nom="$1" cle="$2" ip

    [[ "$nom" =~ ^[A-Za-z0-9_-]{1,32}$ ]] \
        || erreur "nom invalide (lettres, chiffres, - et _ uniquement, 32 caractères max)"
    [[ "$cle" =~ ^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw480]=$ ]] \
        || erreur "clé publique invalide (44 caractères base64 terminés par « = » attendus)"
    [ "$cle" != "$(cat "$CLE_PUBLIQUE")" ] \
        || erreur "c'est la clé publique du SERVEUR : il faut celle affichée par l'application cliente"
    ! grep -qxF "# admin: $nom" "$WG_CONF" || erreur "un administrateur « $nom » existe déjà"
    ! grep -qF "PublicKey = $cle" "$WG_CONF" || erreur "cette clé est déjà déclarée"

    ip="$(prochaine_ip)"
    printf '\n# admin: %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' \
        "$nom" "$cle" "$ip" >> "$WG_CONF"
    echo "  + administrateur « $nom » ajouté avec l'adresse $ip"
    appliquer
    afficher_modele_client "$ip"
}

retirer() {                       # $1 = nom
    verifier_root retirer
    verifier_installe
    local nom="$1" tmp
    grep -qxF "# admin: $nom" "$WG_CONF" || erreur "aucun administrateur « $nom »"

    # Supprime le bloc « # admin: <nom> » jusqu'à la ligne vide suivante.
    tmp="$(mktemp)"
    awk -v cible="# admin: $nom" '
        $0 == cible               { saute = 1; next }
        saute && /^# admin: /     { saute = 0 }
        saute && /^[[:space:]]*$/ { saute = 0; next }
        !saute                    { print }
    ' "$WG_CONF" > "$tmp"
    install -m 600 "$tmp" "$WG_CONF"
    rm -f "$tmp"
    echo "  - administrateur « $nom » retiré : sa clé ne permet plus aucune connexion."
    appliquer
}

etat() {
    verifier_root etat
    echo "== Service =="
    echo "  au boot : $(systemctl is-enabled "wg-quick@$WG_IF" 2>/dev/null || echo non)"
    echo "  actif   : $(systemctl is-active "wg-quick@$WG_IF" 2>/dev/null || echo non)"
    echo "== Écoute UDP $WG_PORT =="
    ss -ulnp 2>/dev/null | grep ":$WG_PORT " | sed 's/^/  /' || echo "  (rien n'écoute)"
    echo "== Tunnel =="
    wg show "$WG_IF" 2>/dev/null | sed 's/^/  /' || echo "  (interface absente)"
    echo "== Administrateurs déclarés =="
    if [ -f "$WG_CONF" ] && grep -q "^# admin: " "$WG_CONF"; then
        grep "^# admin: " "$WG_CONF" | sed 's/^# admin: /  - /'
    else
        echo "  (aucun)"
    fi
    echo "== NAT : exemptions du tunnel (tête de PREROUTING) =="
    iptables -t nat -S PREROUTING 2>/dev/null | grep -E -- "-i $WG_IF |--dport $WG_PORT " \
        | sed 's/^/  /' || echo "  (aucune !)"
    echo "== INPUT : tête de chaîne =="
    iptables -S INPUT 2>/dev/null | sed -n '2,4p' | sed 's/^/  /'
    echo "== Pare-feu du tunnel ($CHAINE) =="
    iptables -S "$CHAINE" 2>/dev/null | sed 's/^/  /' || echo "  (chaîne absente)"
    echo "== Transfert interdit (FORWARD / DOCKER-USER) =="
    { iptables -S FORWARD 2>/dev/null; iptables -S DOCKER-USER 2>/dev/null; } \
        | grep -- "$WG_IF" | sed 's/^/  /' || echo "  (aucune règle wg0 !)"
}

# ---------- Point d'entrée ----------
case "${1:-}" in
    installer)     installer ;;
    ajouter)       [ $# -eq 3 ] || usage; ajouter "$2" "$3" ;;
    retirer)       [ $# -eq 2 ] || usage; retirer "$2" ;;
    etat)          etat ;;
    pare-feu-up)   verifier_root pare-feu-up; pare_feu_up; echo "  Règles du tunnel (ré)appliquées en tête de chaîne." ;;
    garde-tableau) verifier_root garde-tableau; garde_tableau; echo "  Garde du port $PORT_TABLEAU appliquee." ;;
    pare-feu-down) pare_feu_down ;;
    *)             usage ;;
esac
