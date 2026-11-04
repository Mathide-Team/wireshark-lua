# Protocole « 32100 » (P2P des caméras IP, port UDP 32100)

Dissecteur Wireshark Lua du **protocole « 32100 »**, nom donné par l'auteur
au protocole P2P de nombreuses caméras IP grand public qui contactent leurs
serveurs sur UDP 32100 (protocole connu ailleurs sous le nom PPPP / CS2,
documenté dans [lib32100](https://github.com/fbertone/lib32100/wiki)) :
en-tête 0xF1, type et longueur, puis messages STUN, ping, enregistrement /
désenregistrement de l'UID de la caméra, requêtes de connexion, adresses
IP:port échangées, etc. Les types non reconnus sont signalés
(`32100.known == false`).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/fbertone/32100-dissector (fichier `32100_dissector.lua`, version 0.0.3) |
| Commit importé | `5c82c865ed77cfbb9c8d5a0bf3c47fe3c9c5179e` du 21/02/2018 (branche `master`, dernier commit, qui modifie aussi le dissecteur) |
| Licence amont | GPL-3.0-only (`LICENSE` amont : texte de la GPL v3, sans mention « or any later version » propre au projet ; en-tête du fichier : « Author: Fabrizio Bertone ») |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur PPPP / 32100 natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `32100_dissector.lua` | Dissecteur `32100` (UDP 32100), fins de ligne CRLF d'origine conservées |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier. Non importées : les captures
d'écran `images/` du README amont.

## Utilisation

Copier `32100_dissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `32100`. Les échanges caméra ↔ application ↔ relais passent par
d'autres ports : « Décoder comme… » → `32100` sur ces ports (README amont).

## Remarques

- **Recouvrement avec `dissectors/pppp/`** (#175) : même famille de
  protocole. `pppp` est plus complet (heuristique UDP, désobscurcissement
  PSK) ; si les deux sont chargés, le port 32100 revient à celui-ci et les
  autres ports à l'heuristique de `pppp`. Charger l'un ou l'autre selon le
  besoin.
- Globales `messages`, `IoT32100_proto`, `udp_table` comme dans l'amont.
- Plusieurs types sont marqués « ??? » par l'auteur (signification
  supposée) ; projet non maintenu depuis 2018.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
