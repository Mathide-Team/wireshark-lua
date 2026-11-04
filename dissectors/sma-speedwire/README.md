# SMA Speedwire (onduleurs et compteurs solaires)

Dissecteur Wireshark Lua du **protocole SMA Speedwire**, utilisé sur
Ethernet (UDP 9522, multidiffusion) par les onduleurs solaires et compteurs
d'énergie SMA : identifiant `SMA`, entrées étiquetées (groupe, découverte,
adresse IP) et décodage des trames SMA Net 2. Tiré de la bibliothèque Go
`sunny`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/bboehmke/sunny (fichier `wireshark/spw.lua`) |
| Commit importé | `5389c82be7d724a46b1297ec16f3521e05981bc0` du 25/05/2026 (branche `master`, dernier commit ; dernière modification du dissecteur : `036de0c` du 08/06/2021) |
| Licence amont | Apache-2.0 (`LICENSE` amont et en-tête du fichier : « Copyright 2019 Benjamin Böhmke […] Licensed under the Apache License, Version 2.0 ») |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Speedwire natif |

L'issue citait `evcc-io/sunny`, qui n'est plus accessible (404 le
01/11/2026) ; le fichier est repris du dépôt de l'auteur original,
Benjamin Böhmke, dont l'en-tête de copyright figure dans le fichier.

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont). Pas de fichier `NOTICE` amont.

## Fichiers

| Fichier | Rôle |
|---|---|
| `spw.lua` | Dissecteur `spw` (UDP 9522), champs `spw.*` |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête (l'en-tête Apache amont est conservée).

## Utilisation

Copier `spw.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, capturer
le trafic Speedwire du réseau local et filtrer avec `spw`.

## Remarques

- Le commentaire amont mentionne « udp port 12010 » mais le code enregistre
  bien le port 9522 (port Speedwire SMA).
- Variables globales (`udp_table`, fonctions `parse_*`) comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
