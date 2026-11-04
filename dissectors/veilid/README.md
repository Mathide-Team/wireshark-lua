# Veilid

Dissecteur Wireshark en Lua pur pour le protocole pair-à-pair [Veilid](https://veilid.com)
(issue #49). Il couvre les enveloppes (ENV0/ENV1), les reçus (RCP0), les
trames VLD0/VLD1, le réassemblage des fragments sur UDP, TCP et WebSocket, et
le déchiffrement optionnel des opérations (ChaCha20) à partir d'un fichier de
secrets partagés.

## Import

| | |
|---|---|
| Dépôt amont | https://gitlab.com/SuperTeece/veilid-wireshark-dissector |
| Note | Le dépôt cité dans l'issue (`gitlab.com/veilid/veilid-wireshark-dissector`) renvoie 404. Celui-ci est le dépôt de son auteur, retenu sur décision de Mathilde (01/11/2026). |
| Commit importé | `a0a4eb3734df36d78969e831c2b8f4ad00e1930f` du 06/08/2026 |
| Licence amont | MPL-2.0 (`LICENSE` amont, en-tête `SPDX-License-Identifier: MPL-2.0` dans chaque fichier) |
| Natif Wireshark 4.6.4 | Non |

Les fichiers sont repris sans modification ; seule une en-tête SPDX et de provenance a été ajoutée (convention #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/veilid.lua` | Point d'entrée : enregistrement du protocole, heuristiques UDP/TCP/WebSocket |
| `src/veilid/*.lua` | Modules : champs, enveloppes, reçus, réassemblage, déchiffrement, statistiques |
| `tools/veilid-secrets.py` | Extraction des secrets partagés depuis un nœud Veilid |
| `examples/*.pcap` | Captures de test de l'amont (une par type de trame, plus un cas de déchiffrement) |
| `examples/decrypt-secrets.txt` | Secrets de test qui vont avec `decrypt.pcap` |

## Utilisation

Lier ou copier `src/veilid.lua` **et** le dossier `src/veilid/` dans le dossier
des plugins Lua personnels (`~/.local/lib/wireshark/plugins/`). Pour le
déchiffrement, renseigner la préférence `veilid.secrets_file`.

## Licence

MPL-2.0, licence amont conservée.
