# MessagePack-RPC (TCP / WebSocket)

Dissecteur Wireshark Lua de **MessagePack-RPC** (Sony, projet linear-rpc)
sur TCP et WebSocket : réassemblage TCP, décodage des messages
MessagePack avec la bibliothèque **lua-MessagePack**, puis affichage du
type (requête 0, réponse 1, notification 2), de l'identifiant `msgid`,
de la méthode, des paramètres, de l'erreur et du résultat (valeurs
converties en texte). Ports par défaut : TCP 9003-9004 et 37800,
WebSocket 9005-9009 (préférences de protocole).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/linear-rpc/msgpack-rpc-dissector (fichiers `msgpack_rpc.lua` et `msgpack_rpc_1_x.lua`) |
| Commit importé | `0d1d7994f7c02032808f4daa787e54a4db6316af` du 07/09/2018 (branche `master`, dernier commit ; dernière modification des deux scripts : `f6d8f51` du 08/04/2016) |
| Licence amont | MIT (fichier `LICENSE`, « Copyright 2015 Sony Corporation », copié ici ; même mention en tête des scripts) |
| Natif Wireshark 4.6.4 | En partie — dissecteur natif `msgpack` (format MessagePack, sans couche RPC ni ports) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `msgpack_rpc.lua` | Protocole `msgpack-rpc`, TCP + WebSocket, ports configurables (Wireshark 1.12 et plus) |
| `msgpack_rpc_1_x.lua` | Variante pour Wireshark 1.10 : TCP seulement, ports fixes 9003 et 37800 |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête. La capture d'écran amont n'est pas
importée.

## Dépendance

Les deux scripts font `require "MessagePack"` : il faut installer
`MessagePack.lua` de **lua-MessagePack** (François Perrad, licence MIT,
https://framagit.org/fperrad/lua-MessagePack ; sous-module amont
`deps/lua-MessagePack` au commit `01ece0f60f227b98de25fc2d7c3c5c0dec8d379d`)
dans un dossier du `package.path` de Wireshark. Il n'est pas inclus ici.

## Utilisation

Installer `MessagePack.lua`, puis copier **un seul** des deux scripts
(normalement `msgpack_rpc.lua`) dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), et filtrer avec `msgpack-rpc`
(ex. `msgpack-rpc.type == 0`).

## Remarques

- Les deux variantes déclarent le même protocole `msgpack-rpc` : ne pas
  les charger ensemble.
- Limite amont : une map à clés numériques est affichée comme un tableau
  (Lua ne distingue pas tableaux et maps).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
