# DIFI — Digital IF Interoperability (version du consortium DIFI)

Dissecteur Wireshark Lua des paquets **DIFI** (Digital Intermediate
Frequency Interoperability, transport de signaux FI numérisés au format
VITA 49.2), dans la version maintenue
par le **DIFI Consortium** pour son dépôt de certification. Protocole
`difi` détecté par heuristique UDP (OUI 0x7C386C ou 0x6A621E, type de
paquet 1, 4, 5 ou 6, taille cohérente) : en-tête commun (type, taille,
numéro de séquence, TSI / TSF, Stream ID, OUI, classe, horodatage), puis
paquets de données, de contexte (Standard Flow Signal / Sample Count :
bande passante, fréquences, niveaux, gains, fréquence d'échantillonnage,
format de données…), de version et de commande (Real Time / Sample
Count, champs CAM, identifiants, état de tampon).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/DIFI-Consortium/DIFI-Certification (fichier `wireshark-dissector/difi-dissector.lua`) |
| Commit importé | `6ee49d1e83c89bc4c35da7b3dd1e52c2a2d0063b` du 31/07/2026 (branche `main`, dernier commit ; dernière modification du script : `b1152d9` du 16/09/2025) |
| Licence amont | MIT (`wireshark-dissector/LICENSE` amont, « Copyright (c) 2022 jo-rivera … Submission to DIFI Consortium for use under the MIT license. », copié ici) ; le script n'a pas d'en-tête de licence ; le reste du dépôt amont n'a pas de licence déclarée |
| Natif Wireshark 4.6.4 | Partiel — `packet-vrt.c` (VITA 49, port UDP 4991) décode le format VITA 49 générique, pas les champs propres au profil DIFI |

## Fichiers

| Fichier | Rôle |
|---|---|
| `difi-dissector.lua` | Protocole `difi`, heuristique UDP |
| `LICENSE` | Licence MIT amont |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Non importés : les captures
`example_pcaps/` (hors du dossier sous licence MIT) et
`wireshark-dissector/tests/difi-gnuradio-example.pcapng` (8 Mo, au-delà
de la limite de 1 Mo).

## Utilisation

Copier `difi-dissector.lua` dans le dossier `plugins` de Wireshark, puis
filtrer avec `difi`. Si le dissecteur natif `vrt` prend le trafic (port
4991), le désactiver ou utiliser « Décoder comme… ».

## Remarques

- C'est une évolution du dissecteur de jo-rivera
  (https://github.com/jo-rivera/difi-wireshark-dissector, issue #509),
  avec heuristique UDP, paquets de commande et classes Sample Count.
- Les quelque 50 `ProtoField` et quatre constantes (`DATA_PKT`,
  `CMD_PKT`…) sont des variables globales aux noms parfois génériques
  (`data`, `year`, `day`, `revision`…) : risque de collision avec d'autres
  scripts Lua.
- Non vérifié dans Wireshark ici.
