# ZAP RPC / Cap'n Proto RPC

Dissecteur Wireshark Lua du **protocole RPC de ZAP**, compatible au niveau
filaire avec le **protocole RPC de Cap'n Proto** : découpage en segments
de mots de 8 octets avec réassemblage TCP, décodage des pointeurs
(structures, listes, capacités) et interprétation des messages selon le
schéma RPC Cap'n Proto embarqué (`restore`, `call`, `return`, `finish`,
`release`, `disembargo`…), avec un résumé lisible dans la colonne Info.
Ports TCP et UDP 9090 par défaut, modifiables dans les préférences.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/zap-proto/wireshark (dossier `plugins/` et `Makefile`) |
| Commit importé | `0bb9036244f2ac83f52b4d3eb6f2d6af8568ec92` du 19/06/2026 (branche `main`, dernier commit : « rebrand: ZAP user-facing identity ») |
| Licence amont | Apache-2.0 (fichier `LICENSE`, copié ici ; en-tête de `capnp.lua` : « Copyright 2014, Andreas Stenius », Apache 2.0) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Cap'n Proto / ZAP natif |

Le dépôt amont n'est pas déclaré comme fork sur GitHub, mais son code
provient de https://github.com/kaos/wireshark-plugins (Andreas Stenius,
Apache-2.0) ; la version ZAP en reprend l'historique et renomme les
libellés visibles (« ZAP RPC Protocol », colonne Protocole « ZAP »).

## Fichiers

| Fichier | Rôle |
|---|---|
| `capnp.lua` | Protocole `capnp` (« ZAP RPC Protocol ») : décodage du format filaire et des messages RPC |
| `capnp_schema.lua` | Module de registre des schémas, chargé par `require("capnp_schema")` |
| `rpc_capnp.lua` | Schéma `rpc.capnp` de Cap'n Proto compilé en table Lua (généré, sans commentaires) |
| `Makefile` | Génère d'autres schémas : `make schema input=/chemin/schema.capnp` (nécessite l'outil `capnp`) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête des `.lua`. La capture d'écran amont
n'est pas importée.

## Utilisation

Copier les trois fichiers `.lua` **ensemble** dans le même dossier
`plugins` de Wireshark (ex. `~/.local/lib/wireshark/plugins/`) :
`capnp.lua` et `rpc_capnp.lua` chargent le module `capnp_schema` par
`require`, ce qui suppose que ce dossier figure dans `package.path`.
Recharger les plugins Lua, régler le port si besoin, puis filtrer avec
`capnp`.

## Remarques

- Le nom de protocole `capnp` est générique : conflit possible avec un
  autre plugin Cap'n Proto installé en parallèle.
- `rpc_capnp.lua` a été généré à partir de `rpc.capnp` (projet Cap'n
  Proto, licence MIT) ; il ne contient que la structure du schéma.
- Le suivi des requêtes / réponses repose sur l'ordre des paquets
  (avertissement de l'amont) : les identifiants peuvent être mal associés
  lors d'une re-dissection.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
