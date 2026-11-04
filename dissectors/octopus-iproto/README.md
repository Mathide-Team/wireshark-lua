# Octopus — protocoles iProto et Silverbox (« box »)

Dissecteur Wireshark Lua des protocoles binaires d'**Octopus**, serveur de
stockage en mémoire (lignée Silverbox / Tarantool 1.x, Mail.Ru) :

- `iproto` : en-tête iProto de 12 octets petit-boutiste (type de message,
  longueur, *sync*), plusieurs messages par segment, réassemblage TCP,
  distinction requête / réponse / ping (`0xff00`) selon le port ;
- `silverbox` : commandes du module « box » dans les requêtes — insertion,
  sélection, suppression, mise à jour de champs — avec espace d'objets,
  drapeaux, tuples et champs (longueurs varint), et réponses (code et
  message d'erreur, tuples retournés).

Ports TCP 33013 et 3313.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/delamonpansie/octopus (fichier `extra/wireshark/iproto.lua`) |
| Commit importé | `0e08b2a5b50da8d234b1f825be329072615e0697` du 13/03/2021 (branche `master`, dernier commit ; dernière modification de `iproto.lua` : `53e008e` du 22/08/2014) |
| Licence amont | BSD-2-Clause (fichier `LICENSE` : « Copyright (C) 2010-2016 Mail.RU, Copyright (C) 2010-2021 Yury Vostrikov », deux clauses ; GitHub indique `NOASSERTION`) ; copié ici, le script n'a pas d'en-tête |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur iProto / Tarantool natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `iproto.lua` | Protocoles `iproto` et `silverbox`, TCP 33013 et 3313 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `iproto.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `iproto`.

## Remarques

- Ancien protocole iProto binaire d'Octopus / Tarantool 1.5, distinct du
  protocole MessagePack de Tarantool 1.6 et plus (voir aussi
  https://github.com/mikhainin/tarantool-dissector, autre implémentation).
- Le sens requête / réponse est déduit des ports 33013 / 3313 ; sur un
  autre port (« Décoder comme… »), les commandes box ne sont pas détaillées.
- `box_insert` est défini deux fois dans l'amont (la seconde définition
  l'emporte). Utilise `bit.bor` / `bit.lshift` / `bit.band` (bibliothèque
  `bit` fournie par Wireshark 4.4 et plus) ; sur une version plus ancienne
  qui ne fournit que `bit32`, ajouter `bit = bit32` en tête du script.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
