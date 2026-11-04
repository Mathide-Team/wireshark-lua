# RaiBlocks / Nano — protocole réseau des nœuds (2018)

Dissecteur Wireshark Lua du protocole pair-à-pair **RaiBlocks** (ancien nom
de la cryptomonnaie Nano), écrit pour le nœud expérimental en Lua
**prailude** : protocole `raiblocks` — en-tête de message (types
`keepalive`, `publish`, `confirm_req`, `confirm_ack`, `bulk_pull`,
`bulk_push`, `frontier_req`), pairs du keepalive, blocs (sous-protocole
`raiblocks.block`) et réponses `frontier` / `bulk` suivies par connexion
TCP, avec réassemblage TCP ; ports UDP et TCP 7075.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/slact/prailude (fichier `wireshark-raiblocks-dissector.lua`) |
| Commit importé | `ed080adc2429c798b1ee27ee42cdcb8563092b09` du 07/04/2018 (branche `master`, dernier commit ; dernière modification du script : `5be70bf` du 22/02/2018) |
| Licence amont | MIT (`LICENSE.txt` amont, « Written in 2017-2018 by slact (Leo Ponomarev) », copié ici sous le nom `LICENSE`) ; le script n'a pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Oui — `packet-nano.c` (protocole `nano`, UDP/TCP 7075 + heuristiques), plus complet et à jour |

## Fichiers

| Fichier | Rôle |
|---|---|
| `wireshark-raiblocks-dissector.lua` | Protocole `raiblocks`, UDP/TCP 7075 |
| `LICENSE` | Licence MIT amont |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier le script dans le dossier `plugins` de Wireshark, puis filtrer avec
`raiblocks`. Désactiver le dissecteur natif `nano` (ou utiliser « Décoder
comme… ») pour éviter le conflit sur le port 7075.

## Remarques

- **Dépendance lourde** : le script fait `require "prailude"` et lève une
  erreur au chargement si le paquet est absent. `prailude` (luarocks) est
  un nœud complet avec modules C (blake2b, argon2, balance…) et dépendances
  (`luv`, `lua-cjson`, `lsqlite3`…) ; son rockspec exige `lua >= 5.1, < 5.4`,
  donc il n'est pas installable pour le Lua 5.4 de Wireshark 4.6. Le
  dissecteur est vraisemblablement inutilisable en l'état ; il est importé
  pour référence.
- Doublon fonctionnel du dissecteur natif `nano` ; protocole de 2018,
  antérieur aux évolutions récentes de Nano.
- L'état des connexions TCP est conservé dans des tables locales au script,
  sans fonction `init` : il n'est pas réinitialisé au rechargement d'une
  capture.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
