# Wörterbuch — magasin clé-valeur et courtier de messages

Dissecteurs Wireshark Lua de **Wörterbuch** (magasin clé-valeur en
mémoire et courtier de messages publication / abonnement, écrit en Rust)
dont les messages sont du JSON :

- `worterbuch_tcp` : protocole TCP (un message JSON par ligne),
  réassemblage, type de message (première clé JSON), `transactionId`,
  validation par rapport aux types connus des schémas client et serveur,
  résumé dans la colonne Info ; port TCP 8081 (préférence) ;
- `worterbuch_ws` : mêmes messages dans les trames texte WebSocket,
  heuristique sur `ws` et ports TCP optionnels (préférence, vide par
  défaut) ;
- `wb_peer` : messages entre nœuds de l'orchestrateur de cluster
  (JSON sur UDP : battements de cœur et votes, avec `nodeId` et
  priorité), en post-dissecteur sans configuration de port.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/babymotte/worterbuch (fichiers `wireshark-dissector/worterbuch-tcp.lua`, `wireshark-dissector/worterbuch-ws.lua`, `worterbuch-cluster-orchestrator/wireshark/worterbuch-cluster-orchestrator.lua`) |
| Commit importé | `409837f8e408cf68b124b892893eb4dca2714d70` du 31/10/2026 (branche `main`, dernier commit ; dernières modifications : `worterbuch-tcp.lua` `bbe0886` du 21/01/2026, `worterbuch-ws.lua` `8d4cfbd` du 21/01/2026, `worterbuch-cluster-orchestrator.lua` `45e5a06` du 13/06/2026) |
| Licence amont | AGPL-3.0-or-later (fichier `LICENSE` AGPL v3, copié ici ; README : « GNU Affero General Public License v3 or later ») ; les scripts n'ont pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Wörterbuch natif (le JSON est seulement décodé de façon générique) |

L'auteur propose aussi des licences commerciales ; seule l'AGPL v3 ou
ultérieure s'applique à cette copie. La GPLv3 du dépôt permet la
combinaison avec du code AGPLv3 (article 13) ; précédents :
`dissectors/aerospike/`, `dissectors/space-coap/`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `worterbuch-tcp.lua` | Protocole `worterbuch_tcp`, TCP 8081 |
| `worterbuch-ws.lua` | Protocole `worterbuch_ws`, heuristique WebSocket |
| `worterbuch-cluster-orchestrator.lua` | Post-dissecteur `wb_peer` (UDP) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête.

## Utilisation

Copier les scripts voulus dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), **redémarrer** Wireshark (note
amont : le rechargement des plugins Lua ne suffit pas pour `wb_peer`),
puis filtrer avec `worterbuch_tcp`, `worterbuch_ws` ou `wb_peer`.

## Remarques

- Analyse JSON par motifs (`string.match`) : seuls le type, le
  `transactionId` et quelques champs sont extraits ; le message complet est
  affiché en texte.
- `wb_peer` s'exécute sur chaque paquet UDP et ne s'affiche que si la
  charge utile ressemble à un message de cluster.
- Le changement de port TCP de `worterbuch_tcp` ajoute le nouveau port
  sans retirer l'ancien (amont).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
