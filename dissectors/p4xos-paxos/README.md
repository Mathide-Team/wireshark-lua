# P4xos — Paxos dans le plan de données (UDP 34952)

Dissecteur Wireshark Lua des messages **Paxos** de P4xos (consensus
Paxos implémenté dans des commutateurs programmables en P4, démonstrateur
bmv2 / Mininet) : type de message, instance, tour (*round*), tour du vote
(*vround*), identifiant de chemin de données (accepteur) et valeur
(32 octets). Port UDP 34952 (`0x8888`).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/usi-systems/p4xos-public (fichier `scripts/paxos.lua`) |
| Commit importé | `34f81008cf7bd72ce0a2e27eb64a0a3785203b81` du 29/01/2019 (branche `master`, dernier commit ; dernière modification de `paxos.lua` : `ee5b812` du 30/05/2016) |
| Licence amont | Apache-2.0 (fichier `LICENSE`, copié ici ; le script n'a pas d'en-tête) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Paxos natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `paxos.lua` | Protocole `paxos` sur UDP 34952 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `paxos.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `paxos`.

## Remarques

- **Format décalé par rapport au code P4 actuel** : le script (2016) lit
  type 2 octets, instance 4, round 2, vround 2, chemin de données 2,
  valeur 32 ; l'en-tête `p4src/includes/paxos_headers.p4` du même commit
  définit type 1 octet, instance 2, round 1, vround 1, accepteur 8,
  valeur 64. Les champs ne correspondent donc qu'à l'ancienne version.
- Pas de contrôle de longueur (paquet de moins de 44 octets → erreur).
  Le commentaire amont parle du port 8002, le code utilise 34952. Le
  troisième argument `FT_STRING` de `ProtoField.string` n'est pas une
  valeur d'affichage valide (ignoré s'il vaut `nil`). Variables globales
  `p_paxos`, `subtree`, `dissector`, comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
