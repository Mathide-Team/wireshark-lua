# CSS-Simulator — Cortex TC/TM et couches CCSDS

Collection de dissecteurs Wireshark Lua du simulateur de systèmes
spatiaux CSS de l'IRT Saint-Exupéry, qui sert à la recherche en
cybersécurité. Au centre se trouve le protocole Cortex TC : les
télécommandes envoyées au modem Cortex (Safran) par TCP 3020. Il est
accompagné de Cortex TM (télémesure, TCP 3070) et des couches CCSDS
qu'il appelle : CLTU, trame TC, trame TM, Space Packet, Encapsulation
Packet, en-tête et queue SDLS, PUS TC/TM et réseau « CSS Constellation »
(issue #531). Les 17 scripts du dossier amont sont repris ensemble.
Cortex TC dépend en effet de `Cortex_common.lua` (`require`) et passe la
CLTU aux dissecteurs CCSDS.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/IRT-Saint-Exupery/CSS-Simulator (`CSS_Attacks/Dissectors/Dissecteurs_CCSDS/`, 17 fichiers `.lua`) |
| Commit importé | `82457a85ee4c27605836d8e973d19c68b953a8e2` du 15/09/2026 (dernier commit de `main`) ; dernière modification des 17 scripts : commit `348b2cb29ef4e537b4a97b1ad49db269576a5f77` du 25/02/2026 |
| Licence amont | NASA Open Source Agreement 1.3 (`LICENSE.txt` amont : « This software is released under the terms and conditions of the NASA OPEN SOURCE AGREEMENT VERSION 1.3 » ; README amont : « The CSS simulator is also distributed under the NOSA 1.3 License »). Les scripts ne portent aucune mention de licence, seulement « Written by Pierre Bacquet, Thales Alenia Space ». Licence propre au dossier, déclarée `NASA-1.3` (même démarche que `dissectors/sedona-sox` en AFL-3.0) |
| Natif Wireshark 4.6.4 | Non pour Cortex : aucun dissecteur Cortex dans `tshark -G protocols`. Wireshark a un dissecteur `ccsds` natif (Space Packet) sans équivalent Cortex, CLTU ou SDLS |

Texte complet de la licence : fichier `LICENSE.txt` de ce dossier (copie
conforme du `LICENSE.txt` amont). Les scripts sont repris tels quels
(aucune modification de code, fins de ligne CRLF d'origine conservées) ;
seule l'en-tête de provenance de cinq lignes est ajoutée en tête de
chacun (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/Cortex_TC.lua` | Protocole `cortex_tc` (« Cortex TC Protocol », ligne 51) sur TCP 3020 (ligne 365) ; sous-dissecteur par défaut `tc_cltu_02` (ligne 36) |
| `src/Cortex_TM.lua` | Protocole `cortex_tm` (ligne 45) sur TCP 3070 (ligne 369) ; sous-dissecteur par défaut `tm_frame_02` (ligne 35) |
| `src/Cortex_common.lua` | Ports (lignes 20 et 21), conversion d'horodatage, classe de trace `debug` (ligne 52) ; chargé par `require` |
| `src/tc_cltu.lua` | `tc_cltu` (ligne 12), UDP 30002 et TCP 30020 (lignes 107 et 108) |
| `src/tc_frame.lua` | `tc_frame` (ligne 12), UDP 60001 et TCP 60010 (lignes 296 et 297), préférence de configuration SDLS (ligne 32) |
| `src/tm_frame.lua` | `tm_frame` (ligne 12), ports 70001 et 70010 (lignes 493 et 494) |
| `src/space_packet_protocol.lua` | `space_packet_protocol` (ligne 20), « Décoder comme » sur UDP, TCP et `ccsds.pvn` (lignes 183 à 185) |
| `src/encapsulation_packet_protocol.lua` | `encapsulation_packet_protocol` (ligne 12), UDP et TCP 7000 (lignes 99 et 100) |
| `src/sdls_header.lua`, `src/sdls_trailer.lua` | En-tête et queue SDLS (ligne 12 de chacun) |
| `src/tc_pus.lua`, `src/tm_pus.lua`, `src/tm_pus_cuc.lua` | PUS TC (port 50000, lignes 121 et 122), PUS TM (UDP 8001, TCP 8010, lignes 134 et 135), PUS TM CUC (sans port) |
| `src/pus_service_table.lua`, `src/crc16.lua` | Table des services PUS et CRC-16, chargés par `require` |
| `src/dissector_table.lua` | Crée la table `ccsds.pvn` (ligne 6) |
| `src/CSS_Constellation.lua` | `css_netw` (ligne 22), UDP 5011 et 5012 (lignes 107 et 108) |

## Utilisation

Copier les 17 fichiers de `src/` ensemble dans le dossier des plugins Lua
personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »),
puis recharger avec Ctrl+Maj+L. Les `require` y trouvent les modules
communs. Pour que Cortex TC décode la CLTU, régler le sous-dissecteur
sur un nom existant : `-o cortex_tc.subdissector:tc_cltu`. Pour garder
la CLTU en brut : `-o cortex_tc.subdissect:FALSE`. Filtres :
`cortex_tc`, `cortex_tm`, `tc_cltu`, `tc_frame`, `tm_frame`.

## Vérification à l'import

`luac5.4 -p` : OK pour les 17 scripts. tshark 4.6.4, dossier des
plugins : les 13 protocoles sont inscrits. Un seul message au
chargement : « Registering dissector space_packet_protocol … in
dissector table ccsds.pvn, which doesn't support Decode As ». Captures
synthétiques Cortex TC sur TCP 3020, construites d'après le code
(préambule 1234567890, postambule −1234567890, somme de contrôle à
somme nulle) :

| Essai | Résultat |
|---|---|
| Accusé « Clear TC » de 40 octets | décodé : données de réponse, heure d'accusé, « Response status: 0 (Successful) », « TC checksum … (OK) », postambule OK |
| « NOP » (24 octets) | décodé, somme de contrôle OK |
| « Clear TC » avec CLTU, réglages par défaut | « tc_cltu_02 subdissector not found », puis **erreur Lua** ligne 229 de `Cortex_TC.lua` (`attempt to call a nil value (upvalue 'tc_subdissector')`) |
| Même message, `-o cortex_tc.subdissector:tc_cltu` | CLTU, puis trame TC (en-tête primaire, SCID, VCID, longueur) ; la configuration SDLS par défaut suppose un en-tête SDLS. Sur une trame courte : **erreur Lua** ligne 259 de `tc_frame.lua` (`negative length in tvb range`) |
| Même message, `-o cortex_tc.subdissect:FALSE` | décodé, CLTU en brut, somme de contrôle OK |
| Segment de 3 octets | **erreur Lua** ligne 315 de `Cortex_TC.lua` (`Range is out of bounds`) |

Cortex TM, la télémesure CCSDS, PUS et CSS Constellation ont seulement
été vérifiés au chargement, sans capture.

## Limites constatées

- Les sous-dissecteurs par défaut `tc_cltu_02` et `tm_frame_02` (ligne
  36 de `Cortex_TC.lua`, ligne 35 de `Cortex_TM.lua`) n'existent pas
  dans la collection. Il faut régler la préférence, sans quoi chaque
  télécommande avec CLTU provoque une erreur Lua.
- `Cortex_common.lua` remplace la bibliothèque standard Lua `debug` par
  sa propre classe de trace (ligne 52). Cela peut gêner d'autres scripts
  Lua chargés dans la même instance de Wireshark.
- Les numéros 70001 et 70010 de `tm_frame.lua` (lignes 493 et 494)
  dépassent 65535 : ce ne sont pas des ports valides.
- Un message Cortex doit tenir dans un segment TCP : il n'y a ni
  réassemblage ni découpage (« To Do » de l'amont), ni contrôle de
  longueur.
- Les en-têtes SDLS dépendent d'une préférence de `tc_frame` (et de
  `tm_frame`). Il faut la régler selon la mission simulée.
- Pas de capture réelle dans le dépôt amont.
