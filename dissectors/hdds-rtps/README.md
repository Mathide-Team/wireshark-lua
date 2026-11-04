# HDDS RTPS — post-dissecteur RTPS / DDS

Post-dissecteur Wireshark Lua de **HDDS** (implémentation DDS en Rust de
naskel.com) qui ajoute un arbre « HDDS RTPS Extensions » aux paquets
**RTPS** (protocole filaire de DDS) : en-tête (version, fournisseur avec
détection des paquets HDDS, préfixe GUID), sous-messages (DATA, HEARTBEAT,
ACKNACK, GAP, INFO_TS…), numéros de séquence, QoS en ligne (noms de topic
et de type), et décodage optionnel des charges utiles CDR2 à partir d'un
fichier de types JSON. Limité aux ports UDP 7400 à 7500.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/hdds-team/hdds (dossier `tools/wireshark/`) |
| Commit importé | `8701c0b6ad8c44b6b9328dee6ff7b8ac0d4c20d1` du 15/05/2026 (branche `master`, dernier commit ; dernière modification de `hdds_rtps.lua` : `0edc0e2` du 27/02/2026) |
| Licence amont | Apache-2.0 OR MIT (en-tête SPDX du fichier ; `LICENSE` amont : « licensed under either of » Apache 2.0 ou MIT ; `LICENSE-APACHE` et `LICENSE-MIT` copiés ici, © 2025-2026 naskel.com) |
| Natif Wireshark 4.6.4 | Oui pour RTPS — dissecteur natif `rtps`, très complet ; ce script n'apporte que des vues complémentaires propres à HDDS |

## Fichiers

| Fichier | Rôle |
|---|---|
| `hdds_rtps.lua` | Post-dissecteur `hdds` (« HDDS RTPS Extensions ») |
| `install.sh` | Script amont d'installation dans le dossier `plugins` (Linux, macOS, MSYS) |
| `LICENSE-APACHE`, `LICENSE-MIT` | Textes des deux licences au choix |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête du `.lua`. `install.sh` est copié sans
modification.

## Utilisation

Copier `hdds_rtps.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer `./install.sh`, puis
filtrer avec `hdds` (ex. `hdds.submsg.kind == "DATA"`). Préférences dans
Protocoles → HDDS (fichier de types, décodage CDR, hexadécimal brut,
mode verbeux).

## Remarques

- **Probablement inopérant tel quel** (lecture du code, non vérifié dans
  Wireshark) : un post-dissecteur reçoit le tampon de la trame entière
  (en-têtes Ethernet / IP / UDP compris), mais le script cherche le
  magique `RTPS` à l'octet 0 de ce tampon ; sur une capture Ethernet,
  ce test échoue et rien n'est ajouté. Par ailleurs `format_guid` et
  `format_seq_range` sont déclarées `local` après leur utilisation.
- Le fichier de types est « analysé » en l'exécutant comme du code Lua
  (`load("return " .. contenu)`) : n'utiliser que des fichiers de
  confiance.
- Utilise `bit.band` (bibliothèque `bit` fournie par Wireshark 4.4 et
  plus). Pas de capture d'exemple amont.
