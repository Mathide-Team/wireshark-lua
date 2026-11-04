# Chatstutis — messagerie pair-à-pair sur réseau local

Dissecteur Wireshark Lua du protocole de **Chatstutis**, petite messagerie
en mode texte (TUI, C) pair-à-pair sur réseau local, version 1 :

- découverte des pairs par diffusion UDP (port 45678) : version, type
  (Discover / Disconnect), nom d'utilisateur (32 octets) ;
- messages de discussion sur TCP (port 56789) : version, type
  (Chat / Close Connection), expéditeur (32 octets), message (1024 octets).

Le type de paquet est déterminé par sa longueur (34 octets = découverte,
1058 octets = discussion).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/codestutis/chatstutis (fichier `v1/utils/chatstutis.lua`) |
| Commit importé | `aa41df624fb0e23dd1eed9c886e9d633ccefed22` du 13/10/2026 (branche `main`, dernier commit ; dernière modification de `chatstutis.lua` : `5bf16c6` du 11/07/2026) |
| Licence amont | AGPL-3.0-only (fichier `LICENSE` / `v1/LICENSE` AGPL v3, identiques, copié ici sous le nom `LICENSE` ; aucune mention « or later » dans le dépôt, d'où `-only`) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Chatstutis natif |

La GPLv3 du dépôt permet la combinaison avec du code AGPLv3 (article 13) ;
précédents : `dissectors/aerospike/`, `dissectors/space-coap/`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `chatstutis.lua` | Protocole `chatstutis` sur UDP 45678 et TCP 56789 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le programme C n'est pas importé.

## Utilisation

Copier `chatstutis.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `chatstutis`.

## Remarques

- Correspond à l'implémentation C de la **v1** (`v1/src/peer_discovery.h` :
  paquet de découverte de 34 octets sans port). Le `v1/spec.md` amont
  décrit un champ `listening_port` (36 octets) que le script ne décode
  pas (le champ est déclaré mais non enregistré dans `fields`).
- La version actuelle du programme (`src/packets.h`, racine du dépôt)
  utilise un autre format (octet `info` version/type sur 4 bits, longueurs
  variables) : **non pris en charge** par ce dissecteur.
- Pas de réassemblage TCP : un message de 1058 octets segmenté ne sera
  pas reconnu. Pas de capture d'exemple amont ; non vérifié dans Wireshark.
