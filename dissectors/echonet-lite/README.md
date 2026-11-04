# ECHONET Lite (domotique japonaise)

Dissecteur Wireshark Lua du protocole **ECHONET Lite** (version 1.12 de la
spécification du middleware de communication), standard japonais de
domotique et de gestion de l'énergie (HEMS, compteurs intelligents,
climatiseurs, capteurs…) sur UDP 3610 : en-têtes EHD1 / EHD2, identifiant
de transaction, objets source / destination (groupe et classe nommés),
service ESV (symbole), propriétés EPC / PDC / EDT ; noms et décodage des
propriétés pour le profil de nœud (`0x0EF0`) et le capteur
d'ouverture / fermeture (`0x0029`).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/mzyy94/ECHONET-Lite-dissector |
| Commit importé | `609a1256e983f48b049dc203b6aee33f135fdd78` du 31/07/2017 (branche `master`, dernier commit ; version 1.2.1 d'après `ChangeLog.txt`) |
| Licence amont | MIT (`LICENSE` amont, © 2016 Yuki MIZUNO ; même mention dans l'en-tête de chaque fichier Lua) |
| Natif Wireshark 4.6.4 | Non — pas de dissecteur ECHONET Lite dans la branche `release-4.6` des sources Wireshark |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `echonet-lite.lua` | Point d'entrée : protocole `echonetlite`, UDP 3610 |
| `echonet-lite-data.lua` | Décodage d'EDATA (objets, ESV, propriétés) |
| `echonet-lite-epcparser.lua` | Aiguillage vers le décodage des propriétés par classe |
| `echonet-lite-codelist.lua` | Tables de codes (groupes, classes, ESV) |
| `device-superclass.lua` | Propriétés communes de la super-classe des équipements |
| `group-0x0e-node-profile.lua` | Profil de nœud |
| `group-0x00-open-close.lua` | Capteur d'ouverture / fermeture |

Fichiers importés tels quels (fins de ligne CRLF d'origine conservées) ;
seule une en-tête SPDX + provenance de quatre lignes a été ajoutée en tête
de chaque fichier.

## Utilisation

Copier les sept fichiers `.lua` (ou le dossier entier) dans le dossier
`plugins` de Wireshark (ex. `~/.config/wireshark/plugins/` ou
`~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `echonetlite` (par exemple `echonetlite.edata.esv == 0x73`).

## Remarques

- Les modules se chargent entre eux par `require` (même dossier du chemin
  de recherche Lua) et le point d'entrée utilise des fonctions globales
  définies par `echonet-lite-data.lua` ; l'ordre de chargement par
  Wireshark n'est pas vérifié.
- Seules deux classes ont des propriétés nommées ; la signification des
  EDT n'est pas interprétée (TODO amont).
- Documentation amont en japonais ; capture d'écran non reprise.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
