# Pinoccio / uracoli P2P (IEEE 802.15.4)

Dissecteur Wireshark Lua du **protocole pair-à-pair (P2P) uracoli**,
utilisé au-dessus d'IEEE 802.15.4 par le chargeur d'amorçage (bootloader)
des cartes Pinoccio pour la découverte de nœuds et la mise à jour de
micrologiciel par radio (OTA, « wibo ») : type de commande, numéro de
séquence, adresses, et champs propres à chaque commande (ping, réponse de
ping, données wibo, CRC…).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Pinoccio/hardware-pinoccio (fichier `firmware/bootloader/p2p-wireshark-dissector.lua`) |
| Commit importé | `d1a92f68f132dda9cf34fb467a885a0325ce4a31` du 17/04/2015 (branche `master`, dernier commit ; dernière modification du dissecteur : `8b7556c` du 06/03/2015) |
| Licence amont | BSD-3-Clause (en-tête du fichier : « This file is licensed under the terms of the Modified BSD license », texte des trois clauses ; fichier repris du projet uracoli) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur uracoli P2P natif |

La licence du dépôt Pinoccio (`license.txt`, CERN OHL v1.1) vise les
plans matériels ; le dissecteur porte sa propre licence BSD dans son
en-tête, sans nom de détenteur des droits. Le fichier `LICENSE` de ce
dossier est la copie conforme de la note de licence uracoli fournie dans
le même dépôt (`firmware/bootloader/uracoli-src-20131127/LICENSE` :
« The contents of uracoli is licensed with a Modified BSD License »).

## Fichiers

| Fichier | Rôle |
|---|---|
| `p2p-wireshark-dissector.lua` | Dissecteur `p2p` (heuristique sur `wpan`, et table `wpan.panid`) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête (l'avis BSD amont est conservé).

## Utilisation

Copier `p2p-wireshark-dissector.lua` dans le dossier `plugins` de
Wireshark (ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins
Lua, ouvrir une capture IEEE 802.15.4 (par exemple faite avec le renifleur
uracoli) et filtrer avec `p2p`.

## Remarques

- Le dissecteur s'enregistre avec `wpan.panid` = -1, contournement d'un
  bogue Wireshark de 2014 (bug 10696) ; comportement sous Wireshark 4.6
  non vérifié.
- L'heuristique sur `wpan` peut revendiquer des trames 802.15.4 d'autres
  protocoles (non vérifié).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
