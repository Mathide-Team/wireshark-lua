# NEO P2P — protocole pair-à-pair de la blockchain NEO (2.x)

Dissecteur Wireshark Lua du protocole réseau des nœuds **NEO** dans sa
version 2.x (2018) : en-tête de message (magic MainNet / TestNet /
PrivNet, commande sur 12 octets, longueur, somme de contrôle), puis
décodage des commandes `version`, `addr`, `inv`, `getdata`,
`getheaders`, `getblocks`, `block` et `consensus` (pour les blocs :
transactions, entrées / sorties, attributs, scripts et témoins) ; les
autres commandes (`tx`, `headers`…) n'affichent que l'en-tête. Détection par
heuristique TCP sur la valeur magic, avec réassemblage TCP.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ZhangTao1596/neo-wireshark-plugin (fichier `neo.lua`) |
| Commit importé | `f24c5133d3ed5b94183c76c6cd853ae596acb2ac` du 06/12/2018 (branche `master`, dernier commit ; dernière modification du script : `e49875f` du 08/11/2018, commentaire de version « V1.1.0 2018-11-1 ») |
| Licence amont | MIT (fichier `LICENSE` amont, « Copyright (c) 2018 zhangtao », copié ici) ; le script n'a pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur NEO natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `neo.lua` | Protocole principal `NEOPROTOCOL` (heuristique TCP), protocole `NEO` (champs `neop2p.*`) et 21 sous-protocoles d'affichage |
| `LICENSE` | Licence MIT amont |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Le README amont fait charger le script par `dofile()` depuis `init.lua` ;
il suffit aujourd'hui de copier `neo.lua` dans le dossier `plugins` de
Wireshark. Filtrer avec `neo` (ou `neop2p.cmd == "block"`, par exemple).

## Remarques

- Format NEO 2.x ; le protocole réseau de NEO N3 (2021) est différent et
  n'est pas pris en charge.
- Le script enregistre 23 protocoles, dont beaucoup aux noms génériques
  (`Block`, `Transaction`, `Version`, `Headers`, `Address`, `Consensus`,
  `script`…) : risque de conflit avec d'autres scripts Lua chargés en même
  temps. Faute de frappe amont : `Outpus`. Quelques champs n'ont pas de préfixe
  (`count`, `hashstop`). Les constantes (`M_MAINNET`,
  `NET_TYPE`, `C_…`) sont globales.
- Défaut amont relevé à la lecture : `neo.dissector`, utilisé comme
  dissecteur heuristique, se termine par un `return` sans valeur après
  avoir décodé tous les messages d'un segment, ce qu'un heuristique peut
  interpréter comme un refus.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
