# MAVLink TLOG — lecteur de journaux de télémétrie (shancock884)

Lecteur de fichiers Wireshark en Lua pour les journaux de télémétrie
MAVLink au format TLOG. Ces fichiers sont enregistrés par MAVProxy,
Mission Planner et d'autres stations sol ; ils contiennent les messages
MAVLink échangés avec le véhicule (drone, rover, bateau). Chaque message
complet (en-tête, somme de contrôle, signature éventuelle) y est précédé
d'un horodatage Unix de 8 octets en microsecondes. Ce script n'est pas
un dissecteur : il permet d'ouvrir un `.tlog` dans Wireshark, et le
décodage des messages est confié au plugin Lua MAVLink officiel
(issue #547).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/shancock884/wireshark-tlog-reader (`mavlink-tlog-reader.lua`) |
| Commit importé | `0e6b96610de9f6c547a04e8e70d216b490aca301` du 16/09/2025 (dernier commit de la branche par défaut) ; dernière modification du script : commit `fd0ddd3e53903f979ae6fdaedaaa86822c762acb` du 16/09/2025 |
| Licence amont | MIT (`LICENSE` amont, © 2025 Simon Hancock) ; le script ne porte que le nom de l'auteur, sans mention de licence. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun lecteur TLOG parmi les formats de fichiers, et aucun dissecteur MAVLink dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/mavlink-tlog-reader.lua` | Lecteur de fichiers `FileHandler` « Mavlink Telemetry log file reader », nom court `tlog` (ligne 287), extension `tlog` (ligne 295), inscrit ligne 298. Reconnaissance du fichier par `read_open` (ligne 90) ; lecture de chaque enregistrement par `read_common` (ligne 202). Les paquets sont livrés en encapsulation `USER0` (ligne 119) |

## Utilisation

1. Copier `src/mavlink-tlog-reader.lua` dans le dossier des plugins Lua
   personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »).
2. Pour décoder les messages, générer le plugin MAVLink officiel avec
   pymavlink (voir https://mavlink.io/en/guide/wireshark.html) et le
   copier dans le même dossier, par exemple :
   `python -m pymavlink.tools.mavgen --lang=WLua --wire-protocol=2.0 --output=mavlink_2_common.lua message_definitions/v1.0/common.xml`.
3. Ouvrir le `.tlog` par « Fichier › Ouvrir » (choisir « Tous les
   fichiers », le filtre par défaut ne montre pas `.tlog`), ou
   `tshark -r vol.tlog`.

Sans le plugin MAVLink, les paquets s'affichent « Packet », avec
l'avertissement « User encapsulation not handled: DLT=147 ».

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement. Le
dépôt amont ne contient aucun fichier TLOG. Essais sur des journaux
synthétiques construits avec pymavlink 2.4.50 (messages MAVLink 1 et 2,
dont un signé), non commités. Le décodage utilise un plugin MAVLink
généré par `mavgen` depuis `common.xml` (mavlink/mavlink, commit
`6bf60db` du 29/10/2026), également non commité :

| Essai | Résultat |
|---|---|
| TLOG de 5 messages : HEARTBEAT v2, ATTITUDE, HEARTBEAT v1, SYS_STATUS signé, GPS_RAW_INT | 5 trames de 21, 40, 17, 56 et 42 octets ; horodatages exacts à la microseconde (14:13:20.000000Z, puis +0,250123 s par message) |
| Même fichier avec le plugin MAVLink | « MAVLink 2.0 HEARTBEAT », « ATTITUDE », « MAVLink 1.0 HEARTBEAT », « SYS_STATUS » avec sa signature (« Link id: 1 »), « GPS_RAW_INT » (lat 48.8156000 deg, lon 7.7905000 deg, 12 satellites) ; filtre `mavlink_proto.msgid == 0` : 2 trames |
| Sans le plugin MAVLink | encapsulation « USER 0 (45) », « User encapsulation not handled: DLT=147 » |
| Deuxième enregistrement avec un octet magique faux | lecture arrêtée après la première trame, sans erreur ; message « Lua: Unrecognised Mavlink magic byte 85 » sur la sortie |
| Dernier enregistrement tronqué | lecture arrêtée après la première trame ; message « Lua: read : read_common: failed to read data from file into buffer » |
| Fichier quelconque dont le 9ᵉ octet vaut `0xFD` | pris pour un TLOG, aucune trame lue |
| Capture pcap ordinaire, plugin chargé | ouverte normalement par le lecteur pcap |

## Limites constatées

- Le script ne décode rien lui-même : il faut aussi le plugin MAVLink
  généré par pymavlink, qui n'est pas inclus ici.
- Le débogage est actif (`DEBUG = debug.LEVEL_1`, ligne 26) : les
  erreurs de lecture s'impriment sur la sortie standard (« Lua: … »)
  au lieu d'être signalées par Wireshark. Une erreur au milieu du
  fichier arrête la lecture sans autre avertissement.
- La reconnaissance ne vérifie qu'un octet (le 9ᵉ, `0xFD` ou `0xFE`,
  lignes 100 à 109) : tout fichier qui a cet octet à cette place est
  revendiqué. Le lecteur s'inscrit comme heuristique faible, après les
  formats à signature (pcap, pcapng…).
- Pas d'écriture : `tshark -F tlog` n'est pas pris en charge (lecteur
  seulement, option `"r"` ligne 287). La description du lecteur parle
  par erreur de « Ardupilot DF log file » (ligne 287).
- Les constantes `MAVLINK1_*` et `MAVLINK2_*` (lignes 74 à 78) sont
  des variables globales. Le contrôle de version de Wireshark (ligne 58)
  ne concerne que les versions 1.x.
