# AVE DominaPlus — serveur domotique AVE (WebSocket, port 14001)

Dissecteur Wireshark Lua du **protocole du serveur domotique AVE
DominaPlus** (AVE S.p.A., Italie), échangé entre les clients
(application, tablettes) et le serveur Domina Plus sur WebSocket :
trames `STX commande [GS paramètres] [RS enregistrements] ETX CRC EOT`,
décodage de la commande (liste des zones, des appareils, des commandes
de plan, état et réglage des thermostats, variateurs, éclairage, volets,
scénarios, abonnements aux mises à jour…), des paramètres, des
enregistrements et de leurs champs, et vérification du CRC (XOR des
octets de STX à ETX, soustrait de `0xFF`). Pour les captures TCP brutes,
le script décode lui-même l'en-tête WebSocket (y compris le masquage).
Port TCP 14001.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/pyavedominaplus/pyavedominaplus (dossier `wireshark/`) |
| Commit importé | `670016da82d3c599eabd7bd3d9a13787a6d624c6` du 06/09/2026 (branche `main`, dernier commit ; dernière modification du script : `0a571c8` du 06/09/2026) |
| Licence amont | GPL-3.0-only (`LICENSE` GPL v3 à la racine ; aucun en-tête ni mention « or later » dans le script ou le README) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur AVE natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `ave_dominaplus.lua` | Protocole `ave_domina` : sous-protocole WebSocket `binary`, heuristique WebSocket et TCP 14001 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le reste du dépôt (bibliothèque Python,
script `extract_pcap.py`) n'est pas importé.

## Utilisation

Copier `ave_dominaplus.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer
`wireshark -X lua_script:ave_dominaplus.lua`, puis filtrer avec
`ave_domina`. Champs filtrables : `ave.command`, `ave.param`,
`ave.crc_valid`…

## Remarques

- **`bit32` absent des Wireshark récents** : le décodage WebSocket du
  mode TCP brut appelle `bit32.band` et `bit32.bxor`, bibliothèque de
  Lua 5.2 absente par défaut de Lua 5.3 et 5.4, seules versions prises
  en charge depuis Wireshark 4.4 (qui fournit `bit` à la place). Sans
  `bit32` global, ce chemin échoue (« attempt to index a nil value
  (global 'bit32') ») ; le décodage via le dissecteur WebSocket natif
  n'est pas concerné. Contournement local : ajouter `bit32 = bit` en tête
  du fichier (code amont non modifié ici).
- S'enregistre sur le sous-protocole WebSocket générique `binary` et en
  heuristique sur tout WebSocket : d'autres flux WebSocket binaires
  commençant par `0x02` peuvent être pris pour de l'AVE.
- Les notes amont (README) détaillent des comportements observés sur des
  captures réelles (`WSF` répondu par des `upd WS`, numérotation des
  icônes…) ; ces captures ne sont pas publiées.
- Non vérifié dans Wireshark.
