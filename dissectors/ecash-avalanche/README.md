# eCash Avalanche — post-dissecteur (Bitcoin ABC)

Post-dissecteur Wireshark Lua des messages **Avalanche** du réseau
pair-à-pair **eCash (XEC)**, nœud Bitcoin ABC. Il cherche dans chaque
paquet les en-têtes de message (magiques mainnet, testnet, regtest) et
décode :

- `avapoll` : numéro de tour, inventaires (type — transaction, bloc,
  preuve Avalanche, *stake contender*… — et hachage) ;
- `avaresponse` : tour, délai de refroidissement, compteur de rafale,
  votes (code d'erreur et hachage).

Filtre : `ecash`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Bitcoin-ABC/bitcoin-abc (fichier `contrib/wireshark/ecash_postdissector.lua`) |
| Commit importé | `67a6f6201e2d08e0e401ae4daea2fdd297e12f94` du 01/11/2026 (branche `master`, dernier commit ; dernière modification du script : `3f85d01` du 20/03/2026) |
| Licence amont | MIT (fichier `COPYING` : « Copyright (c) 2009-2026 The Bitcoin developers », « 2009-2017 The Bitcoin Core developers », copié ici sous le nom `LICENSE`) ; le script n'a pas d'en-tête |
| Natif Wireshark 4.6.4 | En partie — le dissecteur natif `bitcoin` décode l'en-tête et les messages classiques, pas les messages Avalanche d'eCash |

## Fichiers

| Fichier | Rôle |
|---|---|
| `ecash_postdissector.lua` | Post-dissecteur `ecash` |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `ecash_postdissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), redémarrer Wireshark, puis
filtrer avec `ecash`. (Note amont : en exécutant Wireshark en root, il
faut utiliser le dossier de plugins global.)

## Remarques

- Post-dissecteur : il parcourt octet par octet chaque paquet capturé à la
  recherche d'un magique, ce qui peut ralentir les grosses captures. Pas
  de réassemblage TCP : un message coupé sur plusieurs segments n'est pas
  décodé.
- Seuls `avapoll` et `avaresponse` sont pris en charge.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
