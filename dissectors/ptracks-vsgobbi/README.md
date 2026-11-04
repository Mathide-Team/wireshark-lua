# PtrackS — pistes radar du simulateur de contrôle aérien de l'ICEA (vsgobbi)

Dissecteur Wireshark Lua des messages « PtrackS » d'un simulateur de
contrôle du trafic aérien de l'ICEA (Instituto de Controle do Espaço
Aéreo, Brésil), écrit par Vitor Sgobbi en 2015. Ces messages texte,
diffusés en multicast sur UDP 1970, portent des pistes d'aéronefs dont
les champs sont séparés par `#` : identifiant du simulateur, type de
message, indicatif, type d'avion, heure, statut, longitude, latitude,
cap, altitude et vitesse (issue #783).

Malgré le titre de l'issue, il ne s'agit pas d'ASTERIX (format
EUROCONTROL, décodé nativement par Wireshark sous `asterix`) : le script
décode le format texte propre au simulateur.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/vsgobbi/PTracksV0.3 (`PtrackSPostDissector.lua`, `packetsPtrackS.pcap`) |
| Commit importé | `25db0d65ba41973820cda5e91dcbc3b02f903b5c` du 08/01/2019 (seul commit du dépôt, « Upload do script em Lua ») ; c'est aussi la dernière modification des deux fichiers |
| Licence amont | « GPL licensed » (ligne 7 du fichier importé : « Created by Vitor Sgobbi, 2015, GPL licensed, Version 0.3 »), sans version précisée ; interprétée à la Wireshark — GPL-2.0-or-later, compatible GPL-3.0-or-later, comme pour `mysql-x-protocol` et `smith-meter` |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur PtrackS dans `tshark -G protocols` |

Le dépôt amont ne contient pas de fichier de licence : la mention
d'en-tête est la seule déclaration de licence (pas de `LICENSE` dans ce
dossier). Le script est repris tel quel (aucune modification de code) ;
seule l'en-tête de provenance de cinq lignes est ajoutée en tête
(convention du dépôt, issue #563). Non importés : une copie de
conflit de la version 0.2 (« conflicted copy 2015-04-17 »), les
extraits de charge utile, le mode d'emploi en PDF et les captures
d'écran.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/PtrackSPostDissector.lua` | Protocole `ptracks` (« PtrackS Protocol », ligne 15) ; champs `ptracks.*` (lignes 25 à 41, liste ligne 44) ; dissecteur ligne 46 ; port UDP 1970 (lignes 109 et 110) ; compteur de paquets par `Listener` (lignes 113 à 129) |
| `captures/packetsPtrackS.pcap` | Capture amont (154 Ko, 672 trames, en-tête Linux « cooked » SLL) : 237 messages PtrackS vers les groupes 235.12.2.4 et 233.12.2.4, mêlés à d'autres trafics (DNS, NTP, HTTP, TLS, ARP) |

## Utilisation

Copier `src/PtrackSPostDissector.lua` dans le dossier des plugins Lua
personnels (`~/.local/lib/wireshark/plugins/`). Le trafic du port UDP
1970 est décodé. Filtres : `ptracks`, `ptracks.callsign`,
`ptracks.alt`, `ptracks.speed`… Malgré son nom, le script n'est pas un
post-dissecteur (l'appel `register_postdissector`, ligne 132, est
commenté).

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : chargement sans erreur, mais
le message « Starting to analyse PtrackS UDP data... » s'affiche sur la
sortie standard (ligne 13). Essais sur la capture amont :

| Essai | Résultat |
|---|---|
| Filtre `ptracks` | 237 paquets (tous les messages du port 1970) ; colonne Protocole toujours « UDP » |
| Piste `SM@1#541#VRN2541#B747#23.8875219822#VN#-919.919253652#1300.29803507#291.558797836#1245.03696945#72.0222…` | arbre décodé mais **valeurs décalées** : « Simulator ID: SM@ », « Message ID: #54 », « Aircraft Call Sign: #VRN254 », « Aircraft type: #B74 », « Altitude: 245.0 », « Speed: 696945 » (au lieu de `SM@1`, `541`, `VRN2541`, `B747`, `1245.03…`, `72.02…`) |
| Messages courts `101#621#(0, 0, 24, 25)` (23 paquets) et `101#551#` (5 paquets) vers 233.12.2.4 | **erreur Lua** lignes 78 et 74 (« Range is out of bounds ») |
| Fin de lecture | « UDP packets from PtrackS = 237 » écrit sur la sortie standard (ligne 125), y compris avec `-T fields` |

## Limites constatées

- Champs lus à des positions fixes (lignes 70 à 104) au lieu d'être
  découpés sur `#` : comme les longueurs varient d'un message à l'autre
  (106 à 107 octets dans la capture), les valeurs sont tronquées ou
  décalées, et les champs `ptracks.*` sont inexploitables pour filtrer.
- Pas de contrôle de longueur : erreur Lua sur les messages de moins
  de 30 octets environ ; les autres types de messages (101#621#,
  101#551#) ne sont pas reconnus.
- `print` au chargement et à la fin de lecture (lignes 13 et 125) :
  pollue la sortie de tshark.
- Colonnes Protocole et Info jamais renseignées.
- Variables globales : `trivial_proto`, les champs `message*`,
  `ip_src_f`, `udp_port_table`, `messageType*`, etc.
