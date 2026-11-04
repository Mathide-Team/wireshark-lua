# ANSI/CTA-852 (LonWorks / LON sur IP, ISO/IEC 14908-4)

Dissecteur Wireshark Lua du protocole **ANSI/CTA-852-A** (ISO/IEC 14908-4,
alias EIA-852 ou CN/IP), qui transporte les trames du bus de terrain
**LonWorks (LON, ISO/IEC 14908-1)** sur IP, très utilisé en gestion
technique du bâtiment. Il décode l'en-tête 852 (version, type de paquet,
extensions, numéro de séquence, horodatage, session) et les paquets de
gestion (enregistrement d'appareil, appartenance au canal, liste d'envoi,
routage du canal, statistiques, accusés, segments, extensions NAT de la
version 1.4), puis la charge LON : PDU, adressage (diffusion de
sous-réseau, groupe, sous-réseau / nœud, Neuron ID), TPDU / SPDU / APDU et
codes de messages LON, avec l'identifiant de transaction dans la colonne
Info.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Gesytec/wireshark_852 (fichier `852LON.lua`, version 1.4) |
| Commit importé | `81b4373255d62ab4f52114a905e3c0036d7967b2` du 25/06/2018 (branche `master`, dernier commit, qui modifie aussi le dissecteur) |
| Licence amont | GPL-3.0-or-later (en-tête du fichier : « This work is licensed under the terms of GPLv3 (or any later version) » ; © Richard T. Brown (Johnson Controls), Volker Schober et Matthias Luerkens (Gesytec) ; `LICENSE` amont : texte de la GPL v3) |
| Natif Wireshark 4.6.4 | **Oui, en partie** — dissecteurs natifs `cnip` (`packet-cnip.c`, CN/IP = EIA-852 sur UDP 1628-1629) et `lon` (`packet-lon.c`) ; ce script Lua en est une alternative plus détaillée sur certains points (extensions NAT, codes de messages), qui remplace le natif sur ces ports une fois chargé |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `852LON.lua` | Protocole `852a` (UDP 1628 et 1629), ≈ 1 170 lignes, fins de ligne CRLF d'origine conservées |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `852LON.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `852a`. Pour revenir au dissecteur natif, désactiver le
protocole `852A` (Analyse → Protocoles activés) et filtrer avec `cnip`.

## Remarques

- **Prend la main sur UDP 1628/1629**, à la place du `cnip` natif.
- Nombreuses variables et fonctions globales (`PACKETTYPE_*`,
  `packetTypeTextTable`, `udp_table`…) comme dans l'amont ; risque de
  collision de noms avec d'autres plugins Lua chargés en même temps.
- Utilise la bibliothèque `bit` (fournie par Wireshark), pas `bit32`.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
