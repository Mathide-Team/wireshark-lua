# libp2p (Identify, GossipSub) et Ethereum Consensus sur QUIC

Dissecteurs Wireshark Lua du projet **ethp2p** pour analyser le trafic
pair-à-pair des clients de consensus Ethereum (Prysm, Lighthouse…), qui
utilisent **libp2p sur QUIC**. Ce sont des post-dissecteurs qui lisent les
champs QUIC natifs (`quic.stream_data`, `quic.stream.stream_id`,
`quic.stream.offset`, `quic.connection.number`) : le trafic doit donc être
déchiffré (fichier de clés TLS).

- `libp2p-common.lua` : bibliothèque partagée (table globale `libp2p`) —
  varints, protobuf minimal, négociation multistream-select, réassemblage
  par flux QUIC, formatage des multiaddr ;
- `libp2p-identify.lua` : protocole `libp2p_identify` (`/ipfs/id/1.0.0`) ;
- `libp2p-gossipsub.lua` : protocole `libp2p_gossipsub`
  (`/meshsub/1.0.0` à `/meshsub/1.3.0`, `/floodsub/1.0.0`) ;
- `eth-consensus.lua` : protocole `eth_consensus` — décompression Snappy
  (en Lua) et décodage SSZ des messages GossipSub PUBLISH de la couche de
  consensus (fork Fulu) pour les sujets `beacon_block`,
  `beacon_aggregate_and_proof`, `beacon_attestation`,
  `sync_committee_contribution_and_proof` et `data_column_sidecar`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ethp2p/wireshark-dissectors |
| Commit importé | `08356b26fc48506e3ac84fea017ad83e83449409` du 23/03/2026 (branche `main`, dernier commit ; dernières modifications : `eth-consensus.lua` `b5887ad`, `libp2p-common.lua` `0659cc6`, `libp2p-gossipsub.lua` et `libp2p-identify.lua` `96da6b8`, tous du 23/03/2026) |
| Licence amont | AGPL-3.0 (fichier `LICENSE` amont, copié ici) ; aucune mention « or later » dans le dépôt, d'où `AGPL-3.0-only` ; les scripts n'ont pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — ni libp2p, ni GossipSub, ni SSZ Ethereum (QUIC et Snappy sont natifs, mais le Snappy natif n'est pas utilisé ici) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `libp2p-common.lua` | Bibliothèque partagée, à installer avec les autres |
| `libp2p-identify.lua` | Post-dissecteur `libp2p_identify` |
| `libp2p-gossipsub.lua` | Post-dissecteur `libp2p_gossipsub` |
| `eth-consensus.lua` | Post-dissecteur `eth_consensus` |
| `CAPTURE.md` | Documentation amont : capturer du trafic QUIC déchiffrable (correctif go-libp2p pour `SSLKEYLOGFILE`, Prysm) |
| `test2.pcap`, `test2-keys.log` | Capture d'exemple amont (≈ 600 Ko) et son fichier de clés TLS de test |
| `LICENSE` | Licence AGPL-3.0 amont |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête des `.lua`. Non importés : `test-data/test.pcap`
(1,7 Mo, au-delà de la limite de 1 Mo) avec ses clés, `test.sh`,
`Makefile`, `CLAUDE.md` et la capture d'écran.

## Utilisation

Copier les quatre `.lua` ensemble dans le dossier `plugins` de Wireshark
(le `Makefile` amont visait `~/.local/lib/wireshark/plugins`). Indiquer le
fichier de clés dans Préférences → Protocols → TLS → « (Pre)-Master-Secret
log filename », puis filtrer avec `libp2p_identify`, `libp2p_gossipsub` ou
`eth_consensus`. Exemple :

```
tshark -r test2.pcap -o tls.keylog_file:test2-keys.log -Y eth_consensus
```

## Remarques

- Chaque script charge `libp2p-common.lua` par `dofile()` depuis son
  propre dossier si la table globale `libp2p` n'est pas encore prête : les
  quatre fichiers doivent rester dans le même dossier.
- Les opérations binaires utilisent la bibliothèque globale `bit`.
- Le décodage SSZ suit les structures du fork Fulu ; d'autres forks
  peuvent être mal décodés.
- Le README amont indique que seules les connexions QUIC sont prises en
  charge (pas TCP/Noise/Yamux).
- `test2-keys.log` ne contient que des secrets TLS de session de la
  capture de test amont.
- Non vérifié dans Wireshark ici (l'amont fournit des tests `tshark`,
  non repris).
