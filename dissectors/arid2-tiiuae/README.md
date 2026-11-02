# ARID2 — identification à distance anonyme des drones (TII)

Dissecteur Wireshark Lua du protocole ARID2 (« Anonymous and Verifiable
Remote Identification »). Il a été conçu par le Technology Innovation
Institute (TII, Abou Dabi) pour l'identification à distance de drones
avec signature de groupe anonyme vérifiable. La trame, sous Ethertype
`0xA21D`, porte l'identifiant de groupe, la position et la vitesse du
drone, la position de l'opérateur, un horodatage, un code d'urgence et
la signature avec sa longueur (issue #538).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/tiiuae/arid2 (`wireshark_dissector/arid.lua`) |
| Commit importé | `60c395e3b21d4669d702ed01354c20c747adb814` du 21/06/2022 (dernier commit de `main`) ; dernière modification du script : commit `d829c299edccdcf338df2438943b6d9d4f6bc7a4` du 27/05/2022 |
| Licence amont | Apache-2.0 (`LICENSE` amont ; README amont : « Distributed under the Apache 2 License » ; aucune mention de licence dans le script, pas de fichier `NOTICE`). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur ARID dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/arid.lua` | Protocole `tii-arid` (« TII ARID Protocol », ligne 6), champs `tii_arid.*` (lignes 9 à 21) ; inscrit dans la table `ethertype` pour `0xA21D` (lignes 28 et 62) |

## Utilisation

Copier `src/arid.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis recharger
avec Ctrl+Maj+L. Dans le projet amont, l'émetteur (`sign.cpp`, bibliothèque
libtins) place la trame après un en-tête 802.1Q (`Dot1Q`, Ethertype
`0xA21D`) dans des trames 802.11 en mode moniteur. L'inscription se fait
dans la table `ethertype` (vérifiée en Ethernet et derrière 802.1Q). Filtres : `tii-arid`,
`tii_arid.group_id`, `tii_arid.timestamp`.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement.
Captures synthétiques construites d'après `sign.cpp` amont (entiers
gros-boutistes, coordonnées multipliées par 10⁶) :

| Essai | Résultat |
|---|---|
| Ethernet, Ethertype `0xA21D`, 50 octets | « TII ARID », « Drone Group ID: cafebabe », champs de position en octets bruts (« Latitude [deg]: 02e8e1d8 »), « Timestamp [s]: 1790000000 », « Emergency Code: 01 », « Signature Length [B]: 7 », signature |
| Même trame derrière une étiquette 802.1Q | décodé de la même façon |
| Trame de 2 octets | **erreur Lua** ligne 47 (`Range is out of bounds`) |

## Limites constatées

- Latitude, longitude, altitude, vitesse et route sont déclarées en
  `bytes` : les valeurs (entiers signés ×10⁶ dans `sign.cpp`) ne sont
  ni converties ni filtrables par valeur.
- Le script appelle le dissecteur `data` avant le sien (ligne 39) : la
  charge apparaît deux fois, en « Data » puis en « TII ARID ».
- La longueur de signature n'est pas utilisée : la signature est lue
  jusqu'à la fin de la trame (ligne 59), FCS ou bourrage compris.
- Les champs sont des variables globales (`len`, `timestamp`, `sign`,
  etc., lignes 9 à 21). Ils peuvent entrer en collision avec d'autres
  scripts Lua.
- Pas de contrôle de longueur : une trame de moins de 43 octets provoque
  une erreur Lua.
- Pas de capture réelle dans le dépôt amont (seulement des copies
  d'écran, non reprises).
