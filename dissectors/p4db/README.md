# P4DB — traitement transactionnel dans le réseau

Dissecteur Wireshark Lua des messages de **P4DB** (prototype de recherche
SIGMOD 2022 « P4DB - The Case for In-Network OLTP », TU Darmstadt —
groupe Data Management Lab) : SGBD distribué dont un commutateur
programmable P4 sert d'accélérateur pour les transactions. Il décode
l'en-tête petit-boutiste (type de message, taille, rang global du client,
numéro de transaction) et, pour LOCK_REQUEST et LOCK_GRANT, l'identifiant
de verrou, le mode et l'octroi. Types nommés : HELLO, SHUTDOWN,
LOCK_REQUEST, LOCK_RELEASE, VOTE_REQUEST, TX_END, TX_ABORT, LOCK_GRANT,
VOTE_RESPONSE, TRANSACTION_END_RESPONSE.

Enregistré sur l'ethertype `0x1001` et le port UDP 4000.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/DataManagementLab/p4db (fichier `tests/wireshark_dissector.lua`, renommé ici `p4db.lua`) |
| Commit importé | `a221708787e23a1394cd116fbefb31f9a5506f4e` du 24/01/2023 (branche `master`, dernier commit ; dernière modification du script : `31e3ae7` du 07/06/2022) |
| Licence amont | Apache-2.0 (fichier `LICENSE`, copié ici ; le script n'a pas d'en-tête) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur P4DB natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `p4db.lua` | Protocole `p4db` sur ethertype `0x1001` et UDP 4000 |

Fichier importé tel quel (seul le nom change) ; seule une en-tête SPDX +
provenance de quatre lignes a été ajoutée en tête.

## Utilisation

Copier `p4db.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `p4db`.

## Remarques

- **Conflit de port** : UDP 4000 est aussi le port du dissecteur natif
  `icq` (ancien protocole ICQ) ; ce script le remplace sur ce port.
- Le champ `expiryTime` est déclaré mais ni enregistré ni utilisé ; les
  octets 12 à 15 ne sont pas affichés ; pas de contrôle de longueur. La
  fonction `get_msg_type` et la variable `length` sont globales, comme
  dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
