# Eufy Security (caméras, protocole P2P local)

Dissecteur Wireshark Lua du **protocole P2P UDP des équipements Eufy
Security** (caméras et HomeBase d'Anker), dérivé de PPPP : types de
messages (requêtes / réponses STUN, LOOKUP, LOCAL_LOOKUP, CHECK_CAM,
DATA, ACK, PING / PONG, fin de session), types de données et codes
d'erreur PPCS, contenu des messages DATA (commandes connues de
l'application).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/JanLoebel/eufy-node-client (fichier `wireshark/eufy_dissector.lua`) |
| Commit importé | `041375a1aca695353cb7d887d99c75184a7805ce` du 06/04/2021 (branche `master`, dernier commit ; dernière modification du dissecteur : `acda734` du 19/12/2020) |
| Licence amont | MIT — déclarée par l'auteur (Jan Löbel) dans `package.json` (`"license": "MIT"`) ; pas de fichier LICENSE ni d'en-tête de licence dans le fichier Lua |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Eufy natif |

Le paquet npm `eufy-node-client` ne restreint pas les fichiers publiés
(pas de champ `files`) : la déclaration MIT couvre l'ensemble du dépôt, y
compris `wireshark/`. L'amont ne fournit pas de texte de licence : texte de
référence de la licence MIT : https://spdx.org/licenses/MIT.html — à
reproduire avec la mention « Copyright (c) Jan Löbel » en cas de
redistribution.

## Fichiers

| Fichier | Rôle |
|---|---|
| `eufy_dissector.lua` | Dissecteur `eufySecurity` (UDP), fins de ligne CRLF d'origine conservées |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `eufy_dissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `eufysecurity`.

## Remarques

- Le script s'enregistre sur la plage UDP `20000-69999` : elle dépasse le
  port maximal (65535) et capte tout le trafic UDP de 20000 à 65535, avec
  de nombreux faux positifs possibles ; à restreindre localement si besoin
  (fichier conservé tel quel ; comportement non vérifié).
- Variables globales (`messages`, `dataTypes`, `udp_table`…) comme dans
  l'amont, susceptibles d'entrer en collision avec d'autres scripts.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
