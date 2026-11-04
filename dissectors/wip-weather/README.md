# WIP — Weather Information Protocol (données météo pour objets connectés)

Dissecteurs Wireshark Lua du **WIP (Weather Information Protocol)**,
protocole UDP léger inspiré de NTP, conçu par un projet étudiant japonais
(U22) pour distribuer aux objets connectés les données publiques de
l'Agence météorologique du Japon : en-tête de 16 octets (version,
identifiant de paquet, type — requête / réponse de localisation, de météo,
de rapport, d'erreur —, drapeaux météo / température / probabilité de
précipitation / alertes / catastrophes / extension, jour, horodatage, code
de zone, somme de contrôle), champs fixes des réponses (code météo,
température, probabilité de précipitation) et enregistrements d'extension
(clé, longueur, données). Ports UDP 4109, 4110 et 4111.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/U22-2025/WIP (dossier `lua/`) |
| Commit importé | `ea9e49fe3f89bc2f3570d1eab0d04fca9070e73a` du 01/09/2025 (branche `main`, dernier commit ; dernière modification des dissecteurs : `bc084f1` du 11/07/2025) |
| Licence amont | MIT (`LICENSE` amont, © 2025 WIP Project) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur WIP natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `wip_dissector.lua` | Protocole `wipv1` : version la plus complète (champs fixes des réponses : code météo, température, probabilité de précipitation) |
| `wireshark.lua` | Protocole `wip-u22` : variante plus ancienne, sans ces champs fixes ; c'est celle que cite le README amont |

Fichiers importés tels quels (commentaires en japonais) ; seule une
en-tête SPDX + provenance de quatre lignes a été ajoutée en tête de chaque
fichier. Le reste du dépôt (serveurs et clients Python / Rust / C++,
configuration) n'est pas importé.

## Utilisation

Copier **un seul** des deux fichiers (de préférence `wip_dissector.lua`)
dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `wipv1` (ou `wip-u22`). Champs filtrables : `wip.type`,
`wip.area_code`, `wip.weather_code`…

## Remarques

- **Ne pas charger les deux fichiers ensemble** : ils déclarent les mêmes
  champs `wip.*` et les mêmes ports UDP 4109-4111 ; le dernier chargé
  prend les ports.
- Le nom « WIP » est celui du projet amont, sans rapport avec d'autres
  protocoles de même sigle.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
