# Ouroboros Network — réseau pair-à-pair de Cardano

Dissecteurs Wireshark Lua de la pile réseau **Ouroboros** de Cardano
(projet IntersectMBO, ex-IOG) :

- `ouroboros_network.lua` : protocole `ouroboros` — en-tête de
  multiplexage (horodatage de transmission, identifiant de mini-protocole
  et sens initiateur / répondeur, longueur), réassemblage TCP, noms des
  messages des mini-protocoles Handshake, ChainSync, BlockFetch,
  TxSubmission, KeepAlive et Peer Sharing (DeltaQueue nommé), puis charge
  utile CBOR passée au dissecteur **CBOR** natif ; port TCP 6061
  (préférence) ;
- `mux.lua` : protocole `mux` (« LeiosDemo ») — uniquement les SDU de
  multiplexage (en-tête et charge utile brute) pour la démonstration Leios
  de `network-mux` ; port TCP 4000.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/IntersectMBO/ouroboros-network (fichiers `ouroboros-network/wireshark-plugin/ouroboros_network.lua` et `network-mux/wireshark-plugin/mux.lua`) |
| Commit importé | `4646039f05eb809bd5252af17121644ec1dc0c2c` du 22/10/2026 (branche `main`, dernier commit ; dernières modifications : `ouroboros_network.lua` `85fe17d` du 28/11/2025, `mux.lua` `a22595a` du 12/05/2026) |
| Licence amont | Apache-2.0 (fichiers `LICENSE` des paquets `ouroboros-network` et `network-mux`, copié ici ; `NOTICE` : « Copyright 2019-2023 Input Output Global Inc (IOG), 2023-2026 Intersect », copié ici) ; les scripts n'ont pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Ouroboros / Cardano natif (le décodage CBOR est natif) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `ouroboros_network.lua` | Protocole `ouroboros`, TCP 6061 |
| `mux.lua` | Protocole `mux` (SDU seuls), TCP 4000 ; renvoie aussi une table de module (`dissectMux`…) |
| `LICENSE`, `NOTICE` | Licence Apache 2.0 et avis de copyright amont |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête des `.lua`.

## Utilisation

Copier le ou les scripts dans le dossier `plugins` de Wireshark (amont :
`~/.config/wireshark/plugins/`), puis filtrer avec `ouroboros` ou `mux`.
Pour un nœud Cardano réel (port 3001 en général), régler le port dans les
préférences du protocole Ouroboros ou utiliser « Décoder comme… ».

## Remarques

- Le port par défaut 6061 est provisoire (commentaire amont « XXX Should
  be something else »). Les deux scripts décodent le même en-tête de
  multiplexage : ne les activer que sur des ports différents.
- Les commentaires d'installation de `mux.lua` citent un ancien chemin
  (`network-mux/demo/mux-leios-demo.lua`).
- La variable `cbor` est globale, comme dans l'amont. Pas de capture
  d'exemple amont ; non vérifié dans Wireshark.
