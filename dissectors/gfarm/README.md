# Gfarm — système de fichiers distribué (protocoles gfm et gfs)

Dissecteurs Wireshark Lua des protocoles de **Gfarm v2**, système de
fichiers distribué en grille (Université de Tsukuba / AIST) :

- `gfarm-gfm` : protocole entre clients / serveurs de fichiers et le
  serveur de métadonnées **gfmd** (TCP 601) — environ 130 noms de
  commandes `GFM_PROTO_*`, décodage des arguments et des réponses
  (association requête / réponse par numéro de requête), drapeaux des
  hôtes, des fichiers, des réplicas, des serveurs de métadonnées… ;
- `gfarm-gfs` : protocole entre clients et serveurs de fichiers **gfsd**
  (TCP 600) — commandes `GFS_PROTO_*` (ouverture, lecture, écriture,
  réplication…).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/oss-tsukuba/gfarm (dossier `util/wireshark/`) |
| Commit importé | `aefbfde261e3376e4adc6cbacf6d9b6837926548` du 29/10/2026 (branche `2.8`, branche par défaut, dernier commit ; dernières modifications des scripts : `gfarm-gfm.lua` `7049c33` du 03/12/2016, `gfarm-gfs.lua` `ca6ed35` du 30/11/2016) |
| Licence amont | BSD-3-Clause d'après l'en-tête des deux fichiers (« Copyright (c) 2011 Software Research Associates, Inc. », trois clauses) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Gfarm natif |

Le `LICENSE` du dépôt Gfarm est une licence permissive propre (© AIST,
Osamu Tatebe) avec des exceptions LGPL pour d'autres dossiers ; les deux
scripts portent leur propre en-tête BSD à trois clauses, retenu ici (le
texte complet de la licence est dans l'en-tête de chaque fichier, aucun
fichier de licence n'est copié).

## Fichiers

| Fichier | Rôle |
|---|---|
| `gfarm-gfm.lua` | Protocole `gfarm-gfm` sur TCP 601 (métadonnées) |
| `gfarm-gfs.lua` | Protocole `gfarm-gfs` sur TCP 600 (serveurs de fichiers) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête.

## Utilisation

Copier les deux fichiers dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `gfarm-gfm` ou `gfarm-gfs`. (Les commentaires amont décrivent
l'ancienne méthode `dofile` dans `init.lua`.)

## Remarques

- **`require("bit")`** en tête des deux scripts : la note amont dit de
  mettre cette ligne en commentaire pour Wireshark ≥ 2.0 (Lua ≥ 5.2). Si le
  chargement échoue sur « module 'bit' not found », commenter la ligne ;
  le reste utilise `bit.band`, fourni par Wireshark 4.4 et plus.
- Limites amont : certaines commandes gfm ne sont pas détaillées, et les
  paquets fragmentés sur plusieurs segments TCP ne sont pas correctement
  décodés. Les connexions authentifiées en TLS / GSI chiffré ne sont pas
  lisibles.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
