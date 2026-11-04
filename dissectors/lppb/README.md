# LPPB — Protocol Buffers préfixés par leur longueur (TCP)

Dissecteur Wireshark Lua **LPPB** (« Length Prefixed Protocol Buffers ») :
il découpe un flux TCP en blocs préfixés par leur longueur (taille du
préfixe configurable, 4 octets par défaut, gros-boutiste), avec
réassemblage (`dissect_tcp_pdus`), et passe chaque message à un
dissecteur Protobuf choisi par son nom de message (préférence « Schema »,
ex. `MY.PROTOBUF.MESSAGE`). Le port TCP est à régler dans les préférences
(0 = désactivé par défaut).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/othrayte/lppb (fichier `lppb.lua`) |
| Commit importé | `956133a736f0339ebd37e83e933b26770967c351` du 01/04/2016 (branche `master`, dernier commit) |
| Licence amont | GPL-3.0-only (fichier `LICENSE` GPL v3, copié ici ; pas de mention « or later » ; le script n'a pas d'en-tête) |
| Natif Wireshark 4.6.4 | En partie — le dissecteur natif `protobuf` décode les messages avec des fichiers `.proto`, mais sans découpage générique « longueur + message » sur TCP |

## Fichiers

| Fichier | Rôle |
|---|---|
| `lppb.lua` | Protocole `lppb`, port TCP configurable |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

1. Installer le plugin **protobuf_dissector** de
   https://github.com/dex/protobuf_dissector (dépendance amont, non
   incluse).
2. Copier `lppb.lua` dans le dossier `plugins` de Wireshark
   (ex. `~/.local/lib/wireshark/plugins/`).
3. Dans Préférences → Protocols → LPPB, régler le port TCP, la taille du
   préfixe et le nom du message (celui du protocole ajouté par
   protobuf_dissector).

## Remarques

- Le script utilise la table de dissecteurs `protobuf.message`, créée par
  protobuf_dissector et **absente** du dissecteur Protobuf natif de
  Wireshark 4.6 : sans ce plugin, chaque paquet décodé produit une erreur
  Lua (lecture du code, non vérifié dans Wireshark).
- Fonctions `get_message_len` et `dissect_message` et champ `len_F`
  globaux, comme dans l'amont. Pas de capture d'exemple amont.
