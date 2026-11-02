# Cerebus — processeurs de signaux neuronaux Blackrock

Dissecteurs Wireshark Lua du protocole UDP **Cerebus**, utilisé entre les
Neural Signal Processors (NSP, Gemini Hub) de **Blackrock Microsystems** et
le PC hôte. Ils décodent les éléments suivants :
- l'en-tête : horodatage, canal `chid`, type, longueur en mots de
  32 bits ;
- les paquets de configuration (`chid` 0x8000) : signal de vie, état et
  niveau de fonctionnement du système, canaux, filtres, tri des
  impulsions, commentaires, journaux… ;
- les paquets de groupe d'échantillons (`chid` 0) ;
- les impulsions `nevPKT_SPK` et les entrées numériques `nevPKT_DIGIN` ;
- plusieurs paquets dans un même datagramme.

Un script est fourni par version du protocole (issue #516).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/CerebusOSS/CerebusWireshark |
| Commit importé | `bf0cb2d4ccb2bc35ed09952d4fec6862519ebd21` du 13/05/2026 (dernier commit de la branche par défaut `master`) ; dernières modifications : `Cerebus311.lua` `ee618cc` (13/05/2026), `Cerebus400.lua` `1475eb0` (13/05/2026), `Cerebus41.lua` `bfd3f93` (13/05/2026), `Cerebus42.lua` `8ba4088` (13/05/2026), `Colours` `dc61c61` (16/03/2017) ; SHA complets dans l'en-tête de chaque script |
| Licence amont | GPL-3.0 (`LICENSE` du dépôt = texte de la GPLv3 ; README : « The dissector is licensed under the GPLv3 »), compatible avec la licence de ce dépôt (GPL-3.0-or-later). Aucune mention « ou ultérieure », d'où `GPL-3.0-only` dans les en-têtes |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur Cerebus dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Les scripts sont repris tels quels (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête de chacun (convention du dépôt, issue #563). `Colours`
(règles de coloration exportées par Wireshark) est copié sans
modification.

## Fichiers

| Fichier | Version du protocole (logiciel embarqué) | Ports UDP |
|---|---|---|
| `src/Cerebus311.lua` | 3.11 (7.0.x), en-tête de 8 octets | 51001 |
| `src/Cerebus400.lua` | 4.0 (7.5), en-tête de 16 octets, type sur 1 octet | 51001 à 51003 |
| `src/Cerebus41.lua` | 4.1 (7.6), en-tête de 16 octets, type sur 2 octets | 51001 à 51003 |
| `src/Cerebus42.lua` | 4.2 (7.8) | 51001 à 51004 |
| `Colours` | règles de coloration (filtres `Cerebus.cbPKT_GENERIC.chid`…) | — |

## Utilisation

Copier **un seul** des quatre scripts, celui qui correspond à la version
du protocole de l'appareil, dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis Ctrl+Maj+L.
Couleurs : « Affichage › Règles de coloration… › Importer… », fichier
`Colours`. Filtres : `cerebus`, `Cerebus.cbPKT_SYSINFO.runlevel`,
`Cerebus.nevPKT_SPK.chid`… Pour un seul appareil Gemini : `udp.port ==
51001` (NSP), `51002` (Hub1) ou `51003` (Hub2).

## Vérification à l'import

tshark 4.6.4 : les quatre scripts se chargent sans erreur (`luac5.4 -p` :
OK). Captures synthétiques construites d'après les définitions de champs
des scripts :

| Essai | Résultat |
|---|---|
| 4.2 : signal de vie (`chid` 0x8000, type 0) | `cbPKT_SYSHEARTBEAT` |
| 4.2 : datagramme de 3 paquets (`SYSREP`, impulsion sur le canal 5, groupe 5) | `cbPKT_SYSINFO (+ 2 others)` ; fréquence 30000 Hz, niveau 50, 8 échantillons `INT16` de l'impulsion, 4 du groupe |
| 4.2 : paquet annonçant 6 mots pour 2 présents | erreur Lua `Range is out of bounds` (ligne 1413 du fichier importé) |
| Mêmes captures avec `Cerebus41.lua` | même décodage (même en-tête) |
| Mêmes captures avec `Cerebus400.lua` | décalage attendu (en-tête 4.0 différent) ; seul le signal de vie est reconnu |
| 3.11 : signal de vie, puis `SYSREP` et paquet canal 5 dans un même datagramme | `cbPKT_SYSINFO (+ 1 other)` ; le canal 5 est affiché `cbPKT_GENERIC` (données brutes) |
| `Cerebus41.lua` et `Cerebus42.lua` chargés ensemble | erreur au chargement : `Proto_new: there cannot be two protocols with the same description` |

## Limites constatées

- Un seul script à la fois : les quatre déclarent le même protocole
  (« Cerebus NSP Communication »). Aucune détection de version : un mauvais
  choix donne un décodage décalé, sans avertissement.
- Paquet tronqué ou longueur `dlen` incohérente : erreur Lua (pas de
  contrôle de longueur avant `buf_remain(0, packet_len)`).
- La colonne Info commence par `NSP:<frame.interface_id>` ; dans un pcap
  classique, sans identifiant d'interface, elle affiche `NSP:nil`.
- `Cerebus311.lua` écrit `Loading cb protocol ...` et `register proto ...`
  sur la sortie standard au chargement (lignes 11 et 1250), ce qui pollue
  les sorties de `tshark`.
- En 3.11, le paquet du canal 5 de l'essai est affiché `cbPKT_GENERIC`
  au lieu de `nevPKT_SPK`, bien que ce type soit défini (ligne 1212).
  Cause non analysée.
- Pas de capture réelle disponible.
