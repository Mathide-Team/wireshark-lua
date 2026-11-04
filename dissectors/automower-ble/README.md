# Husqvarna Automower Connect (BLE)

Dissecteur Wireshark Lua du **protocole BLE propriétaire Husqvarna
Automower Connect**, utilisé pour interroger et commander localement les
tondeuses robotisées Automower : réassemblage des messages répartis sur
plusieurs paquets BLE (post-dissecteur), en-tête, canal, CRC, commande
(majeur / mineur, nommés), longueur et données de requête ou de réponse.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/alistair23/AutoMower-BLE (fichier `husqvarna_automower_protocol.lua`) |
| Commit importé | `c53e3e460aa8f296e57d1f71b410052d86b9f46b` du 09/10/2026 (branche `main`, dernier commit) |
| Licence amont | GPL-3.0-or-later (`LICENSE` amont : GPL v3 ; `pyproject.toml` amont : `GPL-3.0-or-later` ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Automower natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `husqvarna_automower_protocol.lua` | Dissecteur `automower` (post-dissecteur sur le trafic BLE), champs `automower.*` |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `husqvarna_automower_protocol.lua` dans le dossier `plugins` de
Wireshark (ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins
Lua, ouvrir une capture BLE (par exemple un journal HCI Bluetooth Android
« btsnoop », comme le décrit `Wireshark-decoding.md` amont) et filtrer avec
`automower`.

## Remarques

- Protocole obtenu par rétro-ingénierie (bibliothèque non officielle) ;
  toutes les commandes ne sont pas nommées.
- Le dissecteur s'exécute en post-dissecteur sur toutes les trames ; effet
  sur les performances non mesuré.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
