# Sedona Sox / Dasp (automatisation des bâtiments)

Dissecteur Wireshark Lua des protocoles **Dasp** (Datagram
Authenticated Session Protocol, UDP 1876 par défaut) et **Sox** (Sedona
Object eXchange) du **Sedona Framework** (Tridium), utilisé dans des
contrôleurs embarqués d'automatisation de bâtiments et d'IoT : en-tête
Dasp (session, numéro de séquence, type de message, champs d'en-tête,
acquittements), puis commandes Sox (lecture / écriture de composants et
de propriétés, abonnements, événements, fichiers…).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/linsong/sedona (fichier `tools/wireshark/sox.lua`) |
| Commit importé | `406b11f3816fb00db6482640f9cf3397b874b515` du 10/12/2020 (branche `master`, dernier commit ; dernière modification du dissecteur : `22f092b` du 03/05/2019) |
| Licence amont | AFL-3.0 (`LICENSE.md` amont : « Sedona Framework Open Source License », texte de l'Academic Free License v3.0, © Tridium ; README amont : « We use Academic Free License ("AFL"), the same as the official Sedona framework » ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Sox/Dasp natif |

Texte complet de la licence amont : fichier `LICENSE.md` de ce dossier
(copie conforme de l'amont, qui rappelle aussi que la marque « Sedona
Framework » appartient à Tridium et n'est pas concédée).

## Fichiers

| Fichier | Rôle |
|---|---|
| `sox.lua` | Dissecteurs `dasp` (UDP, port réglable dans les préférences, 1876 par défaut) et `sox` |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `sox.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer
`wireshark -X lua_script:sox.lua`, puis filtrer, par exemple :
`(sox.cmd == "c" || sox.cmd == "C") && sox.compId == 1`.

## Remarques

- Le script charge `bit`, puis `bit32` à défaut ; si aucun n'est
  disponible comme module sous Wireshark 4.6 / Lua 5.4, il s'arrête avec
  « sox dissector: bitop module not found » (non vérifié).
- Le port UDP est enregistré dans `dasp_proto.init()`, donc à chaque
  rechargement ; un changement de préférence n'enlève pas l'ancien port.
- Pas de prise en charge des flux Sox (« TODO: stream support » amont).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
