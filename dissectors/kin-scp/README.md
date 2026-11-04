# SCP — Stellar Consensus Protocol (réseau Kin / Stellar Core)

Dissecteur Wireshark Lua des messages du réseau pair-à-pair de
**Stellar Core**, publié par Kin Ecosystem (blockchain Kin, fork de
Stellar) : protocole `scp` — longueur d'enregistrement XDR et réassemblage
TCP, `AuthenticatedMessage` (séquence, HMAC), type de `StellarMessage`,
puis décodage détaillé des seuls messages `TRANSACTION` (enveloppe,
opérations, mémo) et `SCP_MESSAGE` (déclarations PREPARE, CONFIRM,
EXTERNALIZE et NOMINATE, scrutins) ; port TCP 11625. Les clés publiques
sont affichées en adresse Stellar (base32 + CRC16).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/kinecosystem/Wireshark-SCP-Dissector |
| Commit importé | `9803e08b6cd5bc38aa25c42eafc9745077a0a560` du 05/09/2019 (branche `master`, dernier commit ; dernières modifications : `scp.lua` `9803e08` du 05/09/2019, `scp/headers.lua` `7e7d7dc` du 27/05/2019, autres fichiers de `scp/` `6a21241` du 26/05/2019) |
| Licence amont | MIT (fichier `LICENSE` amont, « Copyright (c) 2019 Kin Ecosystem », copié ici) ; `scp/bit.lua` est LuaBit v0.4, « Under the MIT license », copyright (c) 2006~2007 hanzhao ; `scp/basexx.lua` et `scp/crc.lua` n'ont pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Stellar / SCP natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `scp.lua` | Protocole `scp` (et sous-protocoles d'affichage), TCP 11625 |
| `scp/headers.lua` | Définition des `ProtoField` (tables globales) |
| `scp/helpers.lua` | Lecture XDR et conversion des clés en adresses |
| `scp/basexx.lua` | Encodage base32 |
| `scp/crc.lua` | CRC16 XMODEM |
| `scp/bit.lua` | LuaBit v0.4 (opérations binaires en Lua pur) |
| `LICENSE` | Licence MIT amont |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête des `.lua`.

## Utilisation

Comme indiqué en amont, copier `scp.lua` et le dossier `scp/` dans le
dossier `plugins` personnel de Wireshark
(`cp -a scp.lua scp/ ~/.config/wireshark/plugins`), puis filtrer avec `scp`.

## Remarques

- Les modules sont chargés par `dofile("plugins/scp/…")` : ce chemin
  relatif ne fonctionne que si le dossier `scp/` est dans le dossier
  `plugins` du profil personnel de Wireshark.
- `scp/bit.lua` remplace la bibliothèque globale `bit` de Wireshark par
  LuaBit, dont les fonctions ont d'autres noms (`blshift`, `brshift`…, pas
  de `lshift` / `rshift`) : cela peut casser d'autres scripts Lua qui
  utilisent `bit`. LuaBit date de Lua 5.0/5.1 ; son comportement sous
  Lua 5.4 (Wireshark 4.6) n'a pas été vérifié.
- Le script enregistre, en plus de `scp`, des protocoles aux noms très
  génériques (`envelope`, `statement`, `nominate`, `prepare`, `confirm`,
  `ballot`, `externalize`, `tx`, `op`), susceptibles d'entrer en conflit
  avec d'autres scripts ; de nombreuses fonctions et tables
  (`dissectSCP`, `readInt`, `hdr_fields`…) sont globales.
- Seuls `TRANSACTION` et `SCP_MESSAGE` sont détaillés ; le format XDR est
  celui de Stellar Core / Kin en 2019. Coquille amont dans le nom affiché :
  « Stellar Concensus Protocol ».
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
