# HomePlug AV (dissecteur Lua alternatif, adaptateurs CPL)

Dissecteur Wireshark Lua **alternatif** du protocole **HomePlug AV**
(EtherType 0x88E1), utilisé par les adaptateurs CPL (courant porteur en
ligne) pour leurs messages de gestion. Il décode entièrement les messages :

| MMTYPE | Message |
|---|---|
| 0x0014 / 0x0015 | CC_DISCOVER_LIST.REQ / .CNF (stations et réseaux découverts) |
| 0x6034 / 0x6035 | CM_STA_CAP.REQ / .CNF (capacités de la station) |
| 0x6060 / 0x6061 | CM_STA_IDENTIFY.REQ / .CNF (identification, capacités étendues) |
| 0x6046 | CM_MME_ERROR.IND |

avec l'en-tête MME (version, type, fragmentation) et les champs détaillés
(débits, capacités HomePlug Green PHY / AV2, etc.).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/serock/homeplug-av-dissector (fichier `homeplug-av.lua`) |
| Commit importé | `25f11a7bf406208188b0fb3935d63876f4cc9c28` du 29/04/2023 (branche `main`, dernier commit, qui modifie aussi le dissecteur) |
| Licence amont | GPL-2.0-or-later (en-tête du fichier : `SPDX-License-Identifier: GPL-2.0-or-later`, « Copyright (C) 2023 John Serock », « either version 2 of the License, or (at your option) any later version » ; `LICENSE` amont : texte de la GPL v2) |
| Natif Wireshark 4.6.4 | **Oui** — dissecteur natif `homeplug-av` (`packet-homeplug-av.c`), plus large ; ce script est une alternative plus détaillée pour les quelques messages ci-dessus, qui **remplace le natif sur l'EtherType 0x88E1** une fois chargé |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `homeplug-av.lua` | Protocole `homeplugav` (EtherType 0x88E1) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier (l'en-tête SPDX amont est
conservée).

## Utilisation

Copier `homeplug-av.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `homeplugav`. Pour revenir au natif, désactiver le protocole
`HOMEPLUGAV` (Analyse → Protocoles activés) et filtrer avec `homeplug-av`.

## Remarques

- Pas de défragmentation des messages fragmentés ; seul un sous-ensemble
  des messages de gestion est décodé (README amont).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
