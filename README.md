# wireshark-lua

Collection de dissecteurs Wireshark en Lua, repris (imports documentés,
issue par issue) de dépôts tiers listés dans les [issues « dissecteur »](https://github.com/Mathilde-Team/wireshark-lua/issues?q=label%3Adissecteur).

## Structure

Un sous-dossier par dissecteur dans `dissectors/<protocole>/` : les fichiers
Lua importés tels quels de l'amont (en-tête SPDX + provenance ajouté), plus
un `README.md` d'import (source, commit, licence amont, utilisation).

Les amonts sont suivis par `scripts/verifier_mises_a_jour.py`, avec un
rapport hebdomadaire (workflow « Mises à jour amont »). La procédure de mise
à jour est décrite dans [docs/maintenance.md](docs/maintenance.md) (#766).

## Licence

[GPL-3.0-or-later](LICENSE) — Wireshark lui-même est en GPL-2.0-or-later,
compatible avec la GPLv3. Chaque script Lua du dépôt porte l'en-tête
`-- SPDX-License-Identifier: GPL-3.0-or-later` dès l'ajout de code.

## Contribution

Agents et humains : lire d'abord [CLAUDE.md](CLAUDE.md) et la
[mission d'équipe](https://github.com/Mathilde-Team/.github/blob/dev/MISSION.md).

## Version

**0.1.0** — première version du dépôt outillé : collecte de dissecteurs
(importée issue par issue), validation CI des imports et licence
GPL-3.0-or-later. Source de vérité : les tags Git du dépôt (`vX.Y.Z`,
SemVer) ; le tag `v0.1.0` est posé sur le commit de livraison de cette
version sur `main`.
