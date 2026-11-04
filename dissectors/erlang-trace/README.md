# Erlang trace — lecture des fichiers de trace Erlang

Plugin Wireshark Lua qui ouvre directement les **fichiers de trace
Erlang** produits par `dbg:trace_port(file, …)` et décode leur contenu :

- `erlang-trace.lua` : lecteur de fichiers (`FileHandler` « Erlang trace
  file ») — une entrée de trace par paquet, avec horodatage — et
  dissecteur `erlang_trace` : type d'entrée (terme binaire / messages de
  trace perdus), processus, type d'événement, module, fonction, arité ;
- `erlterm.lua` : dissecteur `erlterm` du **format binaire externe des
  termes Erlang** (version 131 : atomes, entiers, flottants, références,
  ports, pids, tuples, listes, binaires, maps…), réutilisable par d'autres
  dissecteurs.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/legoscia/cautious-rotary-phone (fichiers `erlang-trace.lua` et `erlterm.lua`) |
| Commit importé | `e58354fd4cdd46bb17f88a8f870755bd67286ac2` du 13/06/2018 (branche `master`, dernier commit) |
| Licence amont | Apache-2.0 (fichier `LICENSE`, copié ici ; en-tête des deux fichiers : « Copyright 2017 Magnus Henoch », Apache 2.0) |
| Natif Wireshark 4.6.4 | Non pour les fichiers de trace ; le dissecteur natif `erldp` (protocole de distribution Erlang) décode aussi des termes, mais pas ces fichiers |

## Fichiers

| Fichier | Rôle |
|---|---|
| `erlang-trace.lua` | Lecteur de fichiers « Erlang trace file » + protocole `erlang_trace` (heuristique `wtap_file`) |
| `erlterm.lua` | Protocole `erlterm` (format binaire externe des termes Erlang) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête.

## Utilisation

Copier les **deux** fichiers dans le dossier `plugins` du dossier de
configuration personnel de Wireshark (`USER_DIR`, ex.
`~/.config/wireshark/plugins/`) : `erlang-trace.lua` charge
`erlterm.lua` par `dofile(USER_DIR .. "plugins/erlterm.lua")`.

Côté Erlang, tracer vers un fichier avec horodatage :

    dbg:tracer(port, dbg:trace_port(file, "foo.trace")).
    dbg:p(all, [call, timestamp]).

puis ouvrir `foo.trace` dans Wireshark.

## Remarques

- Le chemin `dofile` est fixe : installé ailleurs (ex.
  `~/.local/lib/wireshark/plugins/`), `erlang-trace.lua` ne trouve pas
  `erlterm.lua`. `erlterm.lua` déclare la variable globale
  `erlang_term_proto` et ne se charge qu'une fois.
- Pas de fichier de trace d'exemple amont ; non vérifié dans Wireshark.
