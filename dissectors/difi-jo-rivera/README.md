# DIFI — version d'origine de jo-rivera

Dissecteur Wireshark Lua des paquets **DIFI** (Digital IF
Interoperability, profil de VITA 49.2) selon la spécification DIFI 1.0.0 :
paquets de contexte (Standard Flow Signal Context), de données (Standard
Flow Signal Data) et de version, reconnus en UDP par une heuristique sur
l'OUI DIFI `0x7C386C` (issue #509).

C'est la **première version** du dissecteur que l'auteur a ensuite versée
au DIFI Consortium. La version suivie, plus complète, est déjà importée
dans `dissectors/difi-consortium/` (#502). Ce dossier conserve la version
d'origine archivée pour référence et comparaison. Les deux scripts **ne
peuvent pas être chargés ensemble** (voir Limites).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/jo-rivera/difi-wireshark-dissector (`difi-dissector.lua`), **dépôt archivé** (« This plugin has moved to the DIFI Certification project ») |
| Commit importé | `bfbbf268c0d6efbc130b259013f5f64db63a90e6` du 28/10/2022 (dernier commit de la branche par défaut `main`) ; dernière modification de `difi-dissector.lua` : commit `70a0c9cc12dfdf2d6e0cd13963cd998d2df6ab88` du 29/07/2022 |
| Licence amont | MIT, « Copyright (c) 2022 jo-rivera » (`LICENSE` du dépôt), compatible avec la licence de ce dépôt (GPL-3.0-or-later) |
| Natif Wireshark 4.6.4 | Partiel : `packet-vrt.c` (VITA 49, port UDP 4991) décode le VITA 49 générique, pas les champs DIFI ; rien n'est décodé sur les ports de la capture amont |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code, fins de ligne CRLF conservées) ; seule l'en-tête de
provenance de cinq lignes est ajoutée en tête (convention du dépôt,
issue #563). La capture d'exemple amont
(`tests/difi-gnuradio-example.pcapng`, 8,1 Mo) n'est pas copiée, car elle
est trop volumineuse.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/difi-dissector.lua` | Protocole `difi` (« DIFI Protocol »), dissecteur heuristique UDP (ligne 194) ; aucun port fixe |

## Utilisation

Copier `src/difi-dissector.lua` dans le dossier des plugins Lua personnels
de Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis
Ctrl+Maj+L. Ne pas installer en même temps
`dissectors/difi-consortium/difi-dissector.lua`. Filtres : `difi`,
`difi.stream_id`, `difi.seq_num`, `difi.tsi`, `difi.sample_rate`…

## Vérification à l'import

tshark 4.6.4 : le fichier se charge sans erreur (`luac5.4 -p` : OK).

| Essai | Résultat |
|---|---|
| Capture amont `difi-gnuradio-example.pcapng` (22 624 trames, GNU Radio, UDP 50003) | 22 624 trames `DIFI` : 23 paquets de contexte (150 octets) et 22 601 paquets de données (326 octets) ; aucune erreur ni « Malformed » |
| Synthétique : paquet de version (44 octets) | `Version Flow Signal Context Packet`, CIF0 `0x80000002`, CIF1 `0x0000000c`, version V49 et ICD |
| Synthétique : paquet de contexte tronqué (40 octets) | colonne Protocole `DIFI`, mais aucun arbre ni erreur visible |
| Synthétique : OUI différent | laissé à UDP |
| Chargé avec `difi-consortium` | erreur au chargement : `Proto_new: there cannot be two protocols with the same description` |

Comparaison sur la première trame de contexte de la capture amont :

| Champ | Ce script | `difi-consortium` |
|---|---|---|
| Bandwidth | `83886080000` (valeur brute) | `Bandwidth (Hz): 80000` |
| Sample Rate | `100000` (octets 76 à 83) | `Sample Rate (Hz): 0` |
| State and Event Indicators | `2685009920` (décimal) | `0xa00a0000` |

## Limites constatées

- Valeurs à virgule fixe affichées brutes : fréquences, largeur de bande
  et décalages (radix 20, soit des Hz × 2²⁰), niveau de référence et gain
  (radix 7). `83886080000` correspond à 80 000 Hz.
- Disposition fixe du paquet de contexte (108 octets), sans lecture du
  champ CIF0. Les deux scripts ne lisent pas la fréquence d'échantillonnage
  au même endroit (voir le tableau) ; la capture ne permet pas de dire
  lequel a raison.
- Paquet de contexte de moins de 108 octets : arbre vide, sans erreur
  affichée (`buffer(0, 108)`, ligne 103).
- Colonne Info non renseignée ; pas de paquets de commande (gérés par la
  version `difi-consortium`).
- Même nom de protocole (`DIFI`) et même description que `difi-consortium`,
  d'où le conflit au chargement.
- Une trentaine de variables globales aux noms génériques (`data`, `info`,
  `gain`, `oui`, `tsi`, `cif`, `difi_protocol`, `CONTEXT_PKT`…) : risque de
  collision avec d'autres scripts.
- Le nom d'un paquet de version est affiché « Version Flow Signal Context
  Packet », comme dans le script.
