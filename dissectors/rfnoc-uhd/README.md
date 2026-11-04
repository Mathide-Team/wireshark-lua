# RFNoC / CHDR — radios logicielles USRP d'Ettus Research (UHD)

Dissecteur Wireshark Lua officiel du protocole RFNoC (RF Network on
Chip) des radios logicielles USRP d'Ettus Research (groupe National
Instruments), fourni avec le pilote UHD. Il décode l'en-tête CHDR
(destination, longueur, séquence, métadonnées, type de paquet, fin de
vecteur et de rafale, canal virtuel) puis, selon le type, les paquets de
gestion (sauts et opérations), d'état et de commande de flux, de
transactions de contrôle (adresse, code d'opération, état, données) et
de données avec ou sans horodatage, sur UDP 49153 (issue #825).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/EttusResearch/uhd (`tools/dissectors/lua/rfnoc.lua`, `tools/dissectors/lua/color_rules.rfnoc`) |
| Commit importé | `d1be63490e3f3df22ff2f4ea1315f9aada468562` du 09/10/2026 (dernier commit de la branche par défaut `master`) ; dernière modification de `rfnoc.lua` : commit `3a1083452125080fabcb69d330f26892382d2cfe` du 20/07/2026 (« tools: Update RFNoC dissectors for 8-bit SeqNum ») ; de `color_rules.rfnoc` : commit `b584a7a923596b02d1413cc82cec5090080a45ef` du 20/06/2022 |
| Licence amont | GPL-3.0-or-later : en-tête des deux fichiers (« Copyright 2022 Ettus Research, a National Instruments Brand », « SPDX-License-Identifier: GPL-3.0-or-later ») ; `LICENSE.md` du dépôt (UHD sous GPLv3 par défaut, licence commerciale possible sur demande, texte de la GPLv3). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur RFNoC ni CHDR dans `tshark -G protocols` |

Texte de la licence : fichier `LICENSE.md` de ce dossier (copie
conforme du `LICENSE.md` amont). Les fichiers sont repris tels quels
(aucune modification) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête de `rfnoc.lua` (convention du dépôt, issue #563). Le
dossier amont `tools/dissectors/epan/` contient aussi un dissecteur RFNoC
en C++, à compiler avec Wireshark : il n'est pas importé, ce dépôt ne
regroupant que des dissecteurs Lua.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/rfnoc.lua` | Port UDP 49153 (ligne 17) ; tables de valeurs (lignes 20 à 167) ; champs `rfnoc.*` (lignes 169 à 237) ; protocole `rfnoc` (« RFNoC Protocol », ligne 241) ; préférence de largeur CHDR 64 à 512 bits (ligne 304) ; dissecteur ligne 322 ; métadonnées (ligne 371) ; gestion (lignes 386 et 443), état et commande de flux (lignes 473 et 490), contrôle (ligne 508), données (lignes 577 et 587) ; inscription lignes 598 et 599 |
| `src/color_rules.rfnoc` | Règles de couleur par type de paquet (`rfnoc.PktType`), à importer par Affichage → Règles de coloration |

## Utilisation

Copier `src/rfnoc.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`). Le trafic du port UDP 49153 est
décodé. La largeur CHDR (64 bits par défaut) se règle dans les
préférences du protocole RFNoC. Filtres : `rfnoc`, `rfnoc.PktType`,
`rfnoc.DstEPID`, `rfnoc.SeqNum`, `rfnoc.ctrl.Address`,
`rfnoc.mgmt.OpCode`…

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : chargement sans erreur. Le
dépôt amont ne contient aucune capture. Essais sur une capture
synthétique (UDP 49153, CHDR 64 bits), non commitée ; les positions des
champs ont été comparées à `host/include/uhd/rfnoc/chdr_types.hpp` du
même commit :

| Essai | Résultat |
|---|---|
| Données sans horodatage, 16 octets | « [Data]     ->   2 », en-tête CHDR complet, charge utile de 16 octets |
| Données avec horodatage et fin de rafale | « [DaTS]     ->   2 EOB time: 0x0000000123456789 » |
| Commande de flux « Initialize stream », 1000 octets | « [StrC]   7 ->   2 Initialize stream (packets: 0, bytes: 1000) » |
| État de flux, 5 paquets et 4096 octets transférés | « [StrS]   7 ->   2 Okay (No Error) (packets: 5, bytes: 4096) » |
| Gestion, 1 saut, « node info request » | « [Mgmt]   9 ->   2 node info request », version de protocole 1.0 |
| Contrôle « write » à l'adresse `0x1000`, port source 5, octet 2 de l'en-tête à `0x10` | Info « [Ctrl]   5 ->   2 write cafebabe -> 00001000 » ; arbre « num data: 0 », « src EPID: 16 », mais `Data[0]: 0xcafebabe` affiché (voir limites) |
| Données avec 1 mot de métadonnées | métadonnées affichées à partir de l'octet 16 au lieu de l'octet 8 ; charge utile tronquée de 8 octets (voir limites) |
| Paquet de 3 octets | **erreur Lua** ligne 330 (« Range is out of bounds ») |

## Limites constatées

- Paquets de contrôle : les champs de l'arbre suivent bien
  `chdr_types.hpp` (NumData aux bits 10 à 13, SrcEPID aux bits 16 à 31),
  mais le code lit le nombre de mots de données dans l'octet 2
  (ligne 535, bits 20 à 23, qui appartiennent à SrcEPID) et prend comme
  source de la colonne Info les octets 4 et 5 (ligne 568 : port source
  et numéro de séquence, et non SrcEPID). Les mots de données affichés
  et la source de la colonne Info peuvent donc être faux.
- Métadonnées : `dissect_metadata` (lignes 371 à 384) compte deux fois
  leur longueur ; la zone affichée comme métadonnées et le début de la
  charge utile sont décalés dès qu'il y a des métadonnées.
- Pas de contrôle de longueur minimale : erreur Lua sur un paquet de
  moins de 8 octets ; la longueur CHDR n'est pas comparée à la taille du
  paquet.
- Port UDP 49153 fixe (ligne 17), sans préférence de port.
- Variables globales : tous les champs `pf_*`, `rfnoc_proto`,
  `buf_length`, `dstEpid`, `info` et les fonctions `dissect_*`.
