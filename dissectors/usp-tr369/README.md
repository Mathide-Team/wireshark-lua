# USP (TR-369) — User Services Platform sur MQTT

Dissecteur Wireshark Lua de **USP — User Services Platform** (TR-369 du
Broadband Forum, successeur de TR-069 / CWMP pour la gestion des box et
équipements réseau domestiques), transporté dans les messages MQTT
PUBLISH : enveloppe USP Record (`NoSessionContext`, `SessionContext`,
enregistrements de connexion MQTT / WebSocket / STOMP / UDS, déconnexion)
et message USP interne (les 22 types : GET, SET, ADD, DELETE, OPERATE,
NOTIFY, GET_SUPPORTED_DM, GET_INSTANCES, GET_SUPPORTED_PROTO, REGISTER,
DEREGISTER et leurs réponses, ERROR), avec chemins et valeurs de
paramètres, clés uniques, codes d'erreur et sous-types de notification.
Décodeur protobuf minimal en Lua ; post-dissecteur sur le champ
`mqtt.msg`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/NSIDE-ATTACK-LOGIC/USP-Wireshark-Dissector |
| Commit importé | `ba1e91336388d6d447e80682d0df74585eb146a9` du 03/07/2026 (branche `main`, dernier commit ; dernière modification de `usp_dissector.lua` : `b474cdc` du 11/05/2026) |
| Licence amont | MIT (`LICENSE` amont, © 2026 NSIDE ATTACK LOGIC GmbH ; en-tête : « License: MIT ») |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur USP natif (le dissecteur protobuf générique demande les fichiers `.proto`) |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `usp_dissector.lua` | Protocoles `usp_record` et `usp_msg`, post-dissecteur `usp_postdissector` sur MQTT |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Les captures d'écran amont ne sont pas
importées.

## Utilisation

Copier `usp_dissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `usp_record`, `usp_msg.msg_type == 1` (GET),
`usp_msg.param_path contains "Device.WiFi."`… Pour MQTT sur TLS,
renseigner un fichier de clés TLS (`SSLKEYLOGFILE`) dans les préférences
TLS.

## Remarques

- Limites indiquées par l'amont : transport MQTT seulement (pas
  WebSocket, STOMP ni UDS) ; pas de réassemblage des `SessionContext`
  segmentés ; détection heuristique (d'autres charges MQTT binaires
  peuvent apparaître brièvement comme USP) ; entiers varint exacts
  jusqu'à 2^53.
- Utilise `bit.band` / `bit.rshift` (bibliothèque `bit` fournie par
  Wireshark 4.4 et plus).
- L'auteur indique un développement assisté par IA.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
