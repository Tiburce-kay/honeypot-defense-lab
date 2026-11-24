# Laboratoire GNS3 d'origine

Fichiers du projet GNS3 d'origine (nommé « projet de soutenance »), conservés pour référence.

| Fichier | Contenu |
|---|---|
| `projet-de-soutenance.gns3` | topologie : R1 (c7200), ESW1 (c3745 + NM-16ESW), PC1/PC2 (VPCS), NAT, nuage vers les VMs VirtualBox |
| `R1.cfg` | routage inter-VLAN par sous-interfaces dot1Q, DHCP, NAT — **hash du mot de passe retiré** |
| `ESW1.cfg` | affectation des ports aux VLANs 10/20/30/40/99, trunk vers R1 |

Les images Cisco IOS (`c7200-advipservicesk9-mz.152-4.S5`, `c3745-advipservicesk9-mz.124-25d`)
sont propriétaires : elles ne sont pas fournies. Pour rouvrir ce projet dans GNS3, il faut
disposer de ses propres images ainsi que des VMs VirtualBox. Le lab Docker du dépôt n'en a pas besoin.

Liaisons : PC1 → Fa1/0, PC2 → Fa1/1 (VLAN 30) ; serveur de défense → Fa1/2 (VLAN 10) ;
Kali attaquant → Fa1/3 (VLAN 40) ; poste admin → Fa1/4 (VLAN 99) ; trunk Fa1/15 → R1 Fa0/0 ;
R1 Gi1/0 → NAT (WAN).
