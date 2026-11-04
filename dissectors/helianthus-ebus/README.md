# Helianthus eBUS — bus de chauffage eBUS (Vaillant et autres)

Dissecteur Wireshark Lua des flux **eBUS** (bus série des chaudières,
pompes à chaleur et régulateurs de chauffage — Vaillant, Wolf, Kromschröder…)
produits par l'outil de capture `helianthus-ebus-extcap` du projet
Helianthus : enregistrement « HLTH » (magie, version, type de flux,
drapeaux), événements ENS (envoi / réception d'octets), et trames eBUS
(QQ initiateur, ZZ destinataire, PB / SB = opcode, longueur, données,
CRC, ACK, réponse de l'esclave), avec catalogue de 46 opcodes eBUS
génériques et 11 opcodes Vaillant `0xB5xx`, et affichage brut pour les
opcodes inconnus. S'enregistre sur l'encapsulation `USER0` (type de lien
pcap 147).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Project-Helianthus/helianthus-ebus-wireshark |
| Commit importé | `c8d6ee8d94166e7682d94d730a19e558838db5e2` du 25/08/2026 (branche `main`, dernier commit ; dernière modification du script : `cea2e48` du 18/04/2026) |
| Licence amont | GPL-2.0-or-later (`LICENSE` GPL v2 ; en-tête `SPDX-License-Identifier: GPL-2.0-or-later` ; README : « Licensing follows the Wireshark lane: GPL-2.0-or-later ») |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur eBUS natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `helianthus-ebus.lua` | Protocole `helianthus_ebus` sur l'encapsulation `USER0` |
| `captures/hlth-ebus-edge-cases.pcap` | Capture de test synthétique amont : B524 maître-maître et maître-esclave avec réponse, diffusion FF06, QQ / ZZ invalides |
| `captures/hlth-ens-and-kind-edge-cases.pcap` | Capture de test synthétique amont : événements ENS, types d'enregistrement non pris en charge |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête du script (qui portait déjà sa propre
ligne SPDX, conservée). Non importés : scripts de test et de CI,
générateur Python des captures, documents internes (`AGENTS.md`,
`ARCHITECTURE.md`).

## Utilisation

Copier `helianthus-ebus.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
ouvrir par exemple `captures/hlth-ebus-edge-cases.pcap` et filtrer avec
`helianthus_ebus`. Champs filtrables : `helianthus_ebus.opcode`,
`helianthus_ebus.qq`, `helianthus_ebus.zz`…

## Remarques

- Prend **toute** l'encapsulation `USER0` (DLT 147) : d'autres captures
  utilisant ce type de lien seront décodées comme eBUS tant que le script
  est chargé.
- Compatible avec et sans `bit32` (détection au chargement, opérateurs
  natifs de Lua 5.3+ sinon).
- Le README amont indique un dépôt « bootstrap » : intégration sur
  captures réelles encore en attente ; seules les captures synthétiques
  fournies servent de test.
- Non vérifié dans Wireshark.
