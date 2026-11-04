# Shardagnostic Network — multiplexage réseau (dérivé d'Ouroboros)

Dissecteur Wireshark Lua du protocole `shardagnostic` de
**The-Blockchain-Company** : en-tête de multiplexage (horodatage de
transmission, conversation = mini-protocole et sens initiateur /
répondeur, longueur), réassemblage TCP et nom du message des
mini-protocoles Handshake, ChainSync, BlockFetch, TxSubmission et
KeepAlive (DeltaQueue nommé dans les conversations) ; port TCP 6061.

Il s'agit d'une copie renommée d'une ancienne version du dissecteur
`ouroboros_network.lua` du réseau Cardano (IOG), déjà importé dans
`dissectors/ouroboros-network/` (#484) : même structure, mêmes champs
(préfixe `shardagnostic.` au lieu de `ouroboros.`), sans Peer Sharing ni
passage de la charge utile au dissecteur CBOR.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/The-Blockchain-Company/shardagnostic-network (fichier `shardagnostic-network/wireshark-plugin/shardagnostic_network.lua`) |
| Commit importé | `054398f81a5b0b46498adcb3a2167c2ce8ad2b1f` du 24/10/2022 (branche `main`, dernier commit ; dernière modification du script : `e80b661` du 22/10/2021) |
| Licence amont | Apache-2.0 (fichier `shardagnostic-network/LICENSE`, copié ici ; `NOTICE` : « Copyright 2021 The-Blockchain-Company », copié ici) ; le script n'a pas d'en-tête de licence. Le code d'origine (ouroboros-network d'IOG) est lui aussi sous Apache-2.0 |
| Natif Wireshark 4.6.4 | Non |

## Fichiers

| Fichier | Rôle |
|---|---|
| `shardagnostic_network.lua` | Protocole `shardagnostic`, TCP 6061 |
| `LICENSE`, `NOTICE` | Licence Apache 2.0 et avis de copyright amont |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `shardagnostic_network.lua` dans le dossier `plugins` de Wireshark
(le README amont cite par erreur `ark_network.lua`), puis filtrer avec
`shardagnostic`.

## Remarques

- **Conflit** : même port TCP 6061 (codé en dur ; la table
  `default_settings` n'est pas utilisée) et même format que
  `dissectors/ouroboros-network/ouroboros_network.lua` : ne pas installer
  les deux ensemble.
- Le type de message est lu à l'octet 9 de chaque segment (suppose un
  en-tête de tableau CBOR d'un octet) ; le commentaire amont rappelle
  qu'il peut être faux si un message CBOR est découpé en plusieurs
  segments.
- La fonction `dissectArk` (reliquat d'un autre renommage) et la variable
  `result` sont globales.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
