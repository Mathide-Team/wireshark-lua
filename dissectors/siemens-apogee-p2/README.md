# Siemens APOGEE P2 (Protocol II, gestion technique du bâtiment)

Dissecteur Wireshark Lua du **protocole P2 (« Protocol II ») de Siemens
APOGEE**, protocole propriétaire des automates de gestion technique du
bâtiment (panneaux PXC, réseau ALN / BLN) sur TCP 5033 : réassemblage TCP
avec plusieurs PDU par segment, en-tête de trame (longueurs vérifiées,
séquence, sens), créneaux de routage `[BLN, nœud destination, BLN, nœud
source]`, code d'opération AP2 (jeu complet de noms, « opérandes » codés
dans l'opcode pour 55 familles), puis décodeurs par opération : poussée de
valeurs COV, réplication de la table des nœuds, identité / maintien de
connexion, lecture et commande de points, alarmes et alarmes avancées,
programmation horaire d'équipements, réponses corrélées à leur requête,
codes d'erreur 0x0001–0x0E17 et schéma attendu pour environ 440 opcodes.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/jamesccupps/P2_Wireshark_Dissector_And_P2_Scanner (fichier `p2.lua`, version 2.8) |
| Commit importé | `fec437fc45eca0ec4a36d763c23a560ad4020370` du 14/10/2026 (branche `main`, dernier commit ; dernière modification du dissecteur : `2a6f7f6` du 24/09/2026) |
| Licence amont | MIT (`LICENSE` amont, © 2026 James Cupps) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur APOGEE P2 natif (le `p22` natif est la messagerie X.400, sans rapport) |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `p2.lua` | Dissecteur `p2` (TCP 5033), ≈ 3 760 lignes, fins de ligne CRLF d'origine conservées |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier. Non importés : la référence
`PROTOCOL.md` (≈ 800 Ko), le scanner actif Python (`p2_scanner.py`,
`p2_gui.py`…), le panneau virtuel `virtual_pxc/`, la passerelle BACnet
`bridge/` et leurs tests.

## Utilisation

Copier `p2.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua
(Ctrl+Maj+L), puis filtrer avec `p2` (ex. `p2.operand`). Ponctuellement :
`tshark -X lua_script:p2.lua -r capture.pcapng`. Si P2 tourne sur un autre
port que 5033 : « Décoder comme… » → TCP port → P2.

## Remarques

- Noms d'opcodes et structures reconstitués par l'auteur à partir de
  captures réelles (rétro-ingénierie) ; certains schémas sont « dérivés »
  et marqués comme tels dans l'arbre.
- Utilise la bibliothèque `bit` (fournie par Wireshark), pas `bit32`.
- Le dépôt amont fournit aussi un scanner **actif** (lecture des panneaux) :
  seul le dissecteur passif est importé ici.
- Pas de capture d'exemple amont importée ; non vérifié dans Wireshark.
