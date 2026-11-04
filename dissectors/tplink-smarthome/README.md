# TP-Link Smart Home — prises et ampoules Kasa (port 9999)

Dissecteur Wireshark Lua du **protocole local TP-Link Smart Home** (prises
HS100 / HS110 et autres appareils Kasa pilotés par l'application Kasa) :
après l'en-tête de 4 octets (longueur), déchiffrement du chiffrement par
« XOR à clé automatique » (clé initiale 171, chaque octet chiffré servant
de clé au suivant), affichage du texte en clair puis transmission du JSON
obtenu au dissecteur `json` natif. Port TCP 9999.

## Import

| | |
|---|---|
| Dépôt amont | https://gitlab.com/a.lloyd.l.branch/tplink-smartplug (copie GitLab de https://github.com/softScheck/tplink-smartplug) |
| Commit importé | `3ac643160b04ea0bfa2e0b5b4a11211bc7f305e2` du 08/09/2018 (branche `master`, dernier commit ; dernière modification de `tplink-smarthome.lua` : `244b0f9b` du 28/07/2016, « Initial commit ») |
| Licence amont | Apache-2.0 (`LICENSE` amont ; en-tête du fichier : « Licensed under the Apache License, Version 2.0 », © 2016 softScheck GmbH, Lubomir Stroetmann) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur TP-Link Smart Home natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont). Aucun fichier `NOTICE` amont.

## Fichiers

| Fichier | Rôle |
|---|---|
| `tplink-smarthome.lua` | Protocole `tplink-smarthome` sur TCP 9999, puis dissecteur `json` |

Fichier importé tel quel (fins de ligne CRLF conservées) ; seule une
en-tête SPDX + provenance de quatre lignes a été ajoutée en tête. Il est
identique octet pour octet au `tplink-smarthome.lua` de la branche
`master` de softScheck/tplink-smartplug. Non importés : les clients
Python (`tplink-smartplug.py`, `tddp-client/`), la liste de commandes et
la capture d'écran.

## Utilisation

Copier `tplink-smarthome.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `tplink-smarthome` ou `json`.

## Remarques

- **`bit32` absent des Wireshark récents** : le déchiffrement appelle
  `bit32.bxor`, bibliothèque de Lua 5.2 absente par défaut de Lua 5.3 et
  5.4, seules versions prises en charge depuis Wireshark 4.4 (qui fournit
  `bit` à la place). Sans `bit32` global, la dissection échoue dès le
  premier paquet (« attempt to index a nil value (global 'bit32') ») ;
  contournement local : ajouter `bit32 = bit` en tête du fichier (code
  amont non modifié ici).
- Les octets déchiffrés sont convertis en hexadécimal avec `%x` sans
  zéro de tête : un octet inférieur à `0x10` (retour à la ligne, par
  exemple) décale la conversion et peut corrompre le JSON transmis.
- Seul le chiffrement historique (XOR) est géré, pas le protocole KLAP
  des micrologiciels récents ; pour les appareils Tapo, voir
  `dissectors/tplink-tapo/`.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
