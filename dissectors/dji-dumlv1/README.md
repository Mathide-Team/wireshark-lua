# DJI DUML v1 — communications internes des drones DJI

Dissecteurs Wireshark Lua du protocole DUML v1 (« DJI Universal Markup
Language ») utilisé entre les modules des drones DJI (contrôleur de vol,
caméra, nacelle, batterie, radiocommande, application). Ils décodent
l'en-tête (longueur, version, émetteur et destinataire, numéro de
séquence, type de paquet, jeu de commandes et commande). Plusieurs
centaines de commandes sont décodées : jeux général, caméra, contrôle de
vol, nacelle. S'y ajoutent les formats d'enregistrement de vol (DAT) des
Phantom 3, Mavic Pro et Spark, la batterie du Phantom 3 et un export KML
du vol (issue #524).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/o-gs/dji-firmware-tools (`comm_dissector/wireshark/`, les 14 scripts Lua) |
| Commit importé | `1db36ddf45d8018ea849f0c03c5e45d2f3068844` du 25/10/2026 (dernier commit de `master`) ; dernière modification du dossier : commit `886155087c08b571b79e57b9f6b096f4e72ac886` du 26/04/2025 (`init.lua`, « README for Wireshark 4.4, absolute paths in init.lua ») ; date propre à chaque fichier dans son en-tête |
| Licence amont | GPL-3.0 : `LICENSE` du dépôt (texte GNU GPL v3 ; aucune mention « ou ultérieure » ni en-tête de licence dans les scripts, d'où `GPL-3.0-only`). Compatible avec ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur DJI dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Les scripts sont repris tels quels (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête de chacun (convention du dépôt, issue #563). Les outils
Python amont (`comm_serial2pcap.py`, `comm_dat2pcap.py`, `comm_mkdupc.py`)
ne sont pas importés.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/init.lua` | Point d'entrée : charge les autres scripts par `dofile` depuis `dji_script_path` (ligne 18) |
| `src/dji-dumlv1-proto.lua` | Protocole `dji_dumlv1` (ligne 7) : en-tête DUML v1 et table des commandes ; heuristique sur `usb.bulk` et `tcp` (lignes 3322 et 3323), poignées Bluetooth ATT `0x0018`, `0x0010`, `0x0013` (lignes 3317 à 3319) |
| `src/dji-dumlv1-general.lua`, `-camera.lua`, `-flyc.lua`, `-gimbal.lua` | Charges utiles des jeux de commandes général, caméra, contrôle de vol et nacelle (chargés par `dji-dumlv1-proto.lua`, lignes 525 à 528) |
| `src/dji-p3.lua`, `dji-mavic.lua`, `dji-spark.lua` | Protocoles agrégés `dji_p3`, `dji_mavic`, `dji_spark` : choisissent DUML, enregistrement de vol ou batterie selon le premier octet |
| `src/dji-p3-flyrec-proto.lua`, `dji-mavic-flyrec-proto.lua`, `dji-spark-flyrec-proto.lua` | Enregistrements de vol DAT (`dji_p3_flyrec`, `dji_mavic_flyrec`, `dji_spark_flyrec`) |
| `src/dji-p3-batt-proto.lua` | Batterie du Phantom 3 (`dji_p3_batt`, paquets `0xAB`) |
| `src/dji-write-kml.lua` | Menu « Tools › Export KML from DJI drone flight » (ligne 1749) |

## Utilisation

Comme l'indique le README amont : copier tout `src/` **hors** du dossier
des plugins de Wireshark. Copier ensuite `init.lua` seul dans le dossier
des plugins Lua personnels (« Aide › À propos de Wireshark › Dossiers »).
Y remplacer `dji_script_path = ""` (ligne 18 du fichier importé) par le
chemin **absolu** du dossier, terminé par `/`. Puis redémarrer Wireshark.

Les captures UART produites par `comm_serial2pcap.py` ou `comm_dat2pcap.py`
utilisent un type de lien `DLT_USER` : l'associer au protocole voulu
(« Préférences › Protocols › DLT_USER », par exemple `dji_p3`). En
ligne de commande :
`-o 'uat:user_dlts:"User 0 (DLT=147)","dji_p3","0","","0",""'`. Sur USB
ou TCP, l'heuristique `dji_dumlv1` s'applique seule. Filtres :
`dji_dumlv1`, `dji_p3`…

## Vérification à l'import

- `luac5.4 -p` : OK pour les 14 scripts.
- tshark 4.6.4 avec `init.lua` **tel quel** : échec au chargement
  (`dji-dumlv1-proto.lua:525: attempt to concatenate a nil value (local
  'script_path')`). `script_path` est déduit du chemin du script et vaut
  `nil` sans répertoire. Avec une copie hors dépôt de `init.lua`
  pointant vers `src/` en chemin absolu, tout se charge sans erreur. Le
  repli `bit32` de la ligne 11 de `dji-dumlv1-proto.lua` fonctionne sous
  Lua 5.4.
- Paquets construits avec l'outil amont `comm_mkdupc.py` (CRC exacts) :

| Essai | Résultat |
|---|---|
| TCP, `Version Inquiry` requête (PC → caméra) | heuristique `dji_dumlv1` : longueur, version 1, émetteur `PC (10)` index 1, destinataire `Camera (Ambarella)`, séquence 1234, `Request`, `General`, `Version Inquiry (0x01)`, CRC |
| TCP, réponse `Version Inquiry` de 31 octets | `Hardware Version: P3X_DM368_HW`, `Firmware Loader Version: 01.00.01.11`, `Firmware App Version: 01.04.05.08` |
| TCP, réponse `Version Inquiry` de 28 octets | **erreur Lua** `dji-dumlv1-general.lua:154` (`Range is out of bounds`) |
| TCP, deux paquets dans un segment (`OSD General Data Get` 60 octets, `Gimbal Params Get` 8 octets) | les deux reconnus (Info : « OSD General Data Get, Gimbal Params Get ») ; OSD détaillé (position, vitesses, attitude, états) ; nacelle : **erreur Lua** `dji-dumlv1-gimbal.lua:211` (charge plus courte qu'attendu) |
| TCP, CRC final mis à zéro | décodé sans avertissement (`CRC: 0x0000`) |
| `DLT_USER` 0 associé à `dji_p3`, mêmes paquets | décodés ; paquet tronqué à 6 octets : **erreur Lua** `dji-dumlv1-proto.lua:3211` |

## Limites constatées

- `init.lua` doit être édité (chemin absolu) : sans cela, rien ne se
  charge.
- Ni le CRC d'en-tête ni le CRC final ne sont vérifiés, y compris par
  l'heuristique TCP et USB : tout segment TCP commençant par `0x55` avec
  une longueur plausible est revendiqué (faux positifs possibles).
- Charges utiles plus courtes que le format attendu ou paquets tronqués :
  erreurs Lua au lieu d'avertissements.
- `dji-write-kml.lua` écrit `debug: Tools Menu Handler registered` sur la
  sortie standard à chaque lancement (ligne 1751), ce qui pollue la
  sortie de tshark.
- Variables globales nombreuses (tables de commandes, fonctions
  `dji_*_main_dissector`) ; formats d'enregistrement de vol, batterie et
  export KML non essayés ; pas de capture réelle disponible.
- L'issue #528 (honglan3/dji-sdk-dji-firmware-tools) vise une copie du
  même dépôt datée d'avril 2019, non déclarée comme fork : 8 des 14
  scripts y sont identiques, les 6 autres sont des versions plus
  anciennes.
