# Victure Media — flux audio/vidéo des caméras IP Victure

Dissecteur Wireshark Lua du **protocole média propriétaire des caméras IP
Victure** (et caméras apparentées), issu d'un travail de recherche de
vulnérabilités : taille du message, deux octets de synchronisation, type de
média, octet de contrôle, numéro de séquence, longueur des données,
horodatage, puis données média brutes. Port TCP 16116.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/TKems/Victure-Camera-Vulnerabilities |
| Commit importé | `952d589dc7906d7d849751b2457015c8d93bfc2b` du 05/09/2024 (branche `main`, dernier commit, qui est aussi la dernière modification de `victure.lua`) |
| Licence amont | GPL-3.0-or-later (`LICENSE` GPL v3 ; en-tête du fichier : « either version 3 of the License, or (at your option) any later version », © 2024 Trevor Kems) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Victure natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `victure.lua` | Protocole `victure-media` sur TCP 16116 |

Fichier importé tel quel (fins de ligne CRLF conservées) ; seule une
en-tête SPDX + provenance de quatre lignes a été ajoutée en tête.

## Utilisation

Copier `victure.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `victure-media`. Champs filtrables : `victure.media_type`,
`victure.seqNum`, `victure.timestamp`…

## Remarques

- Le dissecteur suppose un message par segment TCP (pas de réassemblage).
- Les champs et variables sont globaux dans le script amont (pas de
  `local`) ; laissé tel quel.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
