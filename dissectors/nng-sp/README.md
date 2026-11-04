# NNG — protocoles SP (nanomsg next-generation)

Dissecteur Wireshark Lua des **protocoles de scalabilité (SP)** de
[NNG](https://nng.nanomsg.org/) (nanomsg next-generation), bibliothèque
de messagerie distribuée :

- transport **TCP** : poignée de main de 8 octets (`\0SP\0` + identifiant
  de protocole) puis trames préfixées par une longueur de 8 octets, avec
  réassemblage et plusieurs PDU par segment ;
- transport **UDP** expérimental : en-tête de 8 octets (version, opcode
  DATA / CREQ / CACK / DISC / MESH, type, paramètres) ;
- en-têtes SP selon le protocole : PAIR v0/v1 (nombre de sauts),
  PUB/SUB, REQ/REP et SURVEYOR/RESPONDENT (pile de retour / backtrace),
  PUSH/PULL, BUS.

Détection heuristique sur TCP (poignée de main) et UDP, sans port fixe.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/flxo/nng-wireshark-dissector (fichier `nng.lua`) |
| Commit importé | `ca594eb9113100b39ca8502748b8d95be0babe1a` du 07/04/2026 (branche `main`, dernier commit, qui est aussi la dernière modification de `nng.lua`) |
| Licence amont | MIT (fichier `LICENSE`, « Copyright (c) 2026 Felix Obenhuber », copié ici) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur NNG / nanomsg natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `nng.lua` | Protocole `nng`, heuristiques TCP et UDP |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `nng.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `nng`.

## Remarques

- TCP : la détection repose sur la poignée de main ; une capture commencée
  après l'établissement de la connexion ne sera pas reconnue (pas de port
  par défaut — utiliser « Décoder comme… »).
- Seuls les transports TCP et UDP sont couverts (pas IPC, WebSocket ni TLS).
- Utilise `bit.band` (bibliothèque `bit` fournie par Wireshark 4.4 et
  plus). Sur une version plus ancienne qui ne fournit que `bit32`,
  ajouter `bit = bit32` en tête du script.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
