# async-tcp-ip — protocole de chat d'exemple (TCP 2048)

Dissecteur Wireshark Lua du **protocole de chat d'exemple** du dépôt
async-tcp-ip (serveur et client de discussion en C# / .NET, série
d'exemples de programmation TCP/IP asynchrone de Stephen Cleary). Il gère
le réassemblage TCP et décode :

- l'en-tête : préfixe de longueur (4 octets gros-boutiste) et type de
  message (4 octets) — CHAT, BROADCAST, KEEPALIVE, SET_NICKNAME, ACK, NAK ;
- le contenu des messages CHAT (longueur + texte UTF-8) ; les autres types
  sont passés au dissecteur `data`.

Port TCP 2048.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/handlemind/async-tcp-ip (fichier `chat.lua` à la racine ; spécification dans `protocol.md`) |
| Commit importé | `8b3ea3f73e6a220e54bd69a1f3ee5e487660ce4d` du 12/06/2025 (branche `main`, dernier commit ; dernière modification de `chat.lua` : `7f4e621` du 18/01/2025) |
| Licence amont | BSD-3-Clause, d'après l'en-tête de `chat.lua` : « This code is in the Public Domain, or the BSD (3 clause) license if Public Domain does not apply in your country », © 2015-2022 Hadriel Kaplan, Stephen Cleary |
| Natif Wireshark 4.6.4 | Non — protocole d'exemple propre à ce projet |

Le dépôt amont n'a pas de fichier de licence ; seul l'en-tête du script
en définit une. Comme pour `dissectors/clou-hrp/`, la variante BSD-3-Clause
est retenue (le domaine public n'étant pas reconnu partout). Le script est
dérivé du modèle FPM de Hadriel Kaplan (exemple du wiki Wireshark).

## Fichiers

| Fichier | Rôle |
|---|---|
| `chat.lua` | Protocole `chat` (« Sample chat protocol ») sur TCP 2048 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le code C# n'est pas importé.

## Utilisation

Copier `chat.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `chat`.

## Remarques

- **Conflit de nom** : le protocole s'appelle `chat`, comme celui de
  `dissectors/superfunkychat/` ; les deux scripts ne peuvent pas être
  chargés ensemble (« Proto already registered »).
- Seul le contenu des messages CHAT est décodé (pas BROADCAST,
  SET_NICKNAME, ACK/NAK) ; fonctions déclarées globales, comme dans
  l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
