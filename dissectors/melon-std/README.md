# melon_std — protocole RPC standard de melon (dérivé de brpc)

Dissecteur Wireshark Lua du **protocole RPC standard de melon**
(bibliothèque C++ de gottingen, dérivée d'Apache brpc) : en-tête de
12 octets (code magique `MRPC` ou `STRM`, taille du corps, taille des
métadonnées), réassemblage TCP, puis décodage des métadonnées
(`melon.policy.RpcMeta`, `melon.StreamFrameMeta`) et du corps des
requêtes / réponses par le dissecteur **Protobuf** natif de Wireshark,
avec association requête → méthode par `correlation_id`. Détection
heuristique sur TCP.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/gottingen/melon (fichier `tools/wireshark_melon_std.lua`) |
| Commit importé | `f416b6e9255935d6e09529d601dfad7a360740c0` du 26/06/2024 (branche `master`, dernier commit ; dernière modification du script : `253728d` du 24/04/2024) |
| Licence amont | Apache-2.0 d'après l'en-tête du fichier (« Licensed to the Apache Software Foundation (ASF)… Apache License, Version 2.0 ») — voir ci-dessous |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur brpc / melon natif (le décodage Protobuf est natif) |

**Licence.** Le dépôt melon est sous AGPL v3 (fichier `LICENSE`), mais ce
script garde l'en-tête Apache-2.0 de la fondation Apache : c'est une
adaptation de `tools/wireshark_brpc_std.lua` d'Apache brpc (code magique
`PRPC` remplacé par `MRPC`, espaces de noms `brpc` → `melon`). L'en-tête,
propre au fichier, est retenu ; aucun fichier de licence n'est copié (le
`LICENSE` amont est l'AGPL), le texte Apache-2.0 est à
https://www.apache.org/licenses/LICENSE-2.0.

## Fichiers

| Fichier | Rôle |
|---|---|
| `wireshark_melon_std.lua` | Protocole `melon` (« melon_std »), heuristique TCP |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

1. Ajouter dans Wireshark (Préférences → Protocols → ProtoBuf → chemins de
   recherche) le dossier `melon/proto` du dépôt melon, qui contient
   `rpc/melon_rpc_meta.proto`, `rpc/streaming_rpc_meta.proto`, ainsi que
   les `.proto` des services à décoder.
2. Copier `wireshark_melon_std.lua` dans le dossier `plugins` de Wireshark
   (ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
   filtrer avec `melon`.

## Remarques

- Coquille amont dans l'heuristique (`maigc` au lieu de `magic`) : en
  pratique seules les trames `MRPC` sont reconnues, pas `STRM`.
- Le script écrit des messages de débogage dans la console Lua à chaque
  paquet (`LM_DBG`).
- Le décodage du corps dépend des fichiers `.proto` des services
  (non fournis) ; sans eux, seules les métadonnées sont lisibles.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
