# Solarman V5 (onduleurs solaires, protocole cloud)

Dissecteur Wireshark Lua du **protocole cloud Solarman V5**, échangé entre
l'enregistreur (logger Wi-Fi) de micro-onduleurs solaires — Bosswerk MI600
et modèles proches (Bosswerk MI300, Deye SUN600G3 / SUN300G3…) — et le
serveur Solarman, sur TCP 10000 : en-tête V5 (longueur, type de message,
numéros de séquence, numéro de série du logger) et décodage d'une partie
des messages (hello, données, réponses serveur, commandes AT).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/0xb1ff/solarman-dissector |
| Commit importé | `7ad7e11757c2db8459ff34f6370dec85769a22d7` du 28/11/2022 (branche `main`, dernier commit) |
| Licence amont | MIT (`LICENSE` amont, © 2022 0xb1ff ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Solarman natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `solarmanv5.lua` | Dissecteur `SolarmanV5` (TCP 10000), champs `solarmanv5.*` |
| `messages/*.md` | Analyse amont octet par octet des messages (hello, fin de hello, données, réponse serveur, commande AT et réponse), en anglais |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête du fichier Lua.

## Utilisation

Copier `solarmanv5.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, ouvrir
une capture du trafic entre l'onduleur et le serveur cloud (par exemple
`tcpdump` sur le routeur, comme le décrit l'amont) et filtrer avec
`solarmanv5`.

## Remarques

- L'amont précise que le dissecteur ne couvre qu'une partie de son analyse
  (`messages/`) ; le message « heartbeat » cité dans le README amont n'a pas
  de fiche (`decode_heartbeat.md` absent de l'amont).
- Le protocole varie selon les onduleurs (autre implémentation citée dans
  l'issue : marxram/spidr).
- Variables globales (`solarmanv5_protocol`, champs) comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
