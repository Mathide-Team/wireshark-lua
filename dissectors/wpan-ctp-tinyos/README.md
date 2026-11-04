# IEEE 802.15.4 / Collection Tree Protocol (TinyOS)

Dissecteur heuristique Wireshark Lua de la **charge des trames IEEE
802.15.4 émises par des capteurs sans fil TinyOS** utilisant le
**Collection Tree Protocol (CTP)** et la couche **Active Messaging** :
selon l'identifiant 6LoWPAN / AM (0x70 trame de routage, 0x71 trame de
données, 0x72 trame de débogage), il décode les champs CTP (options, THL,
ETX, origine, numéro de séquence, identifiant de collecte, parent…) et la
trame Active Messaging transportée.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/AryanKukreja/wireshark_dissector (fichier `dissector.lua`, renommé `wpan-ctp-dissector.lua` ici) |
| Commit importé | `7f56b23d5bb195551f0d7979a3d21674b0d2b9b1` du 07/11/2019 (branche `master`, dernier commit ; dernière modification du dissecteur : `efb7774` du 06/11/2019) |
| Licence amont | BSD-3-Clause (`LICENSE.txt` amont, © 2019 ABusyProgrammer ; texte BSD modifiée en en-tête du fichier, conservé) |
| Natif Wireshark 4.6.4 | Non — 802.15.4 et 6LoWPAN sont natifs, pas CTP / Active Messaging de TinyOS |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE.txt` amont).

Selon son en-tête, le fichier est une modification du dissecteur P2P de
Pinoccio (`hardware-pinoccio/firmware/bootloader/p2p-wireshark-dissector.lua`),
déjà importé dans `dissectors/pinoccio-p2p/` (#164, BSD-3-Clause) ; les
commentaires de l'auteur d'origine sont conservés dans le fichier.

## Fichiers

| Fichier | Rôle |
|---|---|
| `wpan-ctp-dissector.lua` | Protocole `ctp_protocol` (heuristique sur `wpan`, et table `wpan.panid`) |

Fichier importé tel quel (renommé, le nom amont `dissector.lua` étant trop
générique) ; seule une en-tête SPDX + provenance de quatre lignes a été
ajoutée en tête du fichier.

## Utilisation

Copier `wpan-ctp-dissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
ouvrir une capture 802.15.4 et filtrer avec `ctp_protocol`.

## Remarques

- **Écrase la bibliothèque standard `table`** : le fichier fait
  `table = DissectorTable.get("wpan.panid")` en variable globale (repris de
  l'original Pinoccio), ce qui remplace la bibliothèque Lua `table`
  (`table.insert`, `table.concat`…) pour **tous** les plugins Lua chargés
  après lui. Contournement local : remplacer `table` par une variable
  `local` (code amont non modifié ici).
- **Conflit avec `dissectors/pinoccio-p2p/`** : les deux s'enregistrent sur
  `wpan.panid` = -1 et en heuristique `wpan` ; ne charger que l'un des deux.
- L'heuristique peut revendiquer des trames 802.15.4 d'autres protocoles.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
