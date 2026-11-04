# Infinispan Hot Rod (protocole 4.0 / 4.1)

Dissecteur Wireshark Lua du protocole binaire **Hot Rod** d'Infinispan
(grille de données / cache distribué), versions 4.0 (Infinispan 14.0+) et
4.1 (Infinispan 15.1+). D'après l'amont, 124 des 127 opérations sont
décodées : opérations de cache (GET, PUT, REMOVE, REPLACE, conditionnelles,
en masse), statistiques, itération, compteurs, multimaps, flux (4.1),
transactions XA, authentification SASL, écouteurs clients et filtres de
Bloom, requêtes Ickle et scripts, événements, erreurs. Entiers variables
(vInt / vLong, ZigZag), types de média, topologie, métadonnées des
entrées, et association requête / réponse avec liens entre trames.

Port TCP 11222 et heuristique TCP (tous ports).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/rigazilla/hotrod-dissector (fichier `src/hotrod.lua`, dossier `schemas/`) |
| Commit importé | `19c62707b03503efb34ba8b266c10c5d91ea63e1` du 08/05/2026 (branche `main`, dernier commit, qui est aussi la dernière modification de `hotrod.lua`) |
| Licence amont | Apache-2.0 (fichier `LICENSE`, copié ici ; README : « licensed under the Apache License 2.0 ») ; le script n'a pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Hot Rod / Infinispan natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `hotrod.lua` | Protocole `hotrod` sur TCP 11222 + heuristique TCP |
| `schemas/hotrod40.ksy`, `schemas/hotrod30.ksy` | Schémas Kaitai Struct du protocole (4.0 et 3.0), documentation de référence |
| `schemas/README.md` | Notice amont des schémas |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête du `.lua` (schémas copiés sans
modification). La capture d'écran amont (550 Ko) n'est pas importée.

## Utilisation

Copier `hotrod.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua
(Ctrl+Maj+L), puis filtrer avec `hotrod` (ex. `hotrod.magic == 0xa0` pour
les requêtes, `hotrod.req.opcode == 0x03` pour les GET).

## Remarques

- Seules les versions 4.0 et 4.1 sont décodées (le schéma 3.0 n'est que
  de la documentation) ; hypothèse amont : intelligence client `0x03`
  (HASH_DISTRIBUTION_AWARE).
- Pas de réassemblage TCP (aucun `desegment_len`) : les messages coupés
  sur plusieurs segments ne sont pas recomposés. Les connexions TLS ne sont
  pas lisibles.
- L'heuristique peut ralentir les grosses captures (note amont). Utilise
  `bit.*` (bibliothèque `bit` fournie par Wireshark 4.4 et plus).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
