# Cyphal — dissecteurs d'OpenCyphal (v1.0 et v1.1)

Dissecteurs Wireshark Lua du protocole Cyphal (anciennement UAVCAN v1),
bus de données temps réel pour drones, robots et véhicules spatiaux. Le
dépôt officiel d'OpenCyphal fournit trois scripts : un dissecteur de
session Cyphal v1.1 avec ses transports Cyphal/CAN et Cyphal/UDP, et les
deux anciens dissecteurs v1.0, l'un pour Cyphal/CAN, l'autre pour
Cyphal/UDP (issue #540).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/OpenCyphal/wireshark_plugins (`cyphal_1v1.lua`, `cyphal_1v0_can.lua`, `cyphal_1v0_udp.lua`) |
| Commit importé | `aecadaf274cd03c25f802c9223aa4c301762c593` du 28/08/2026 (dernier commit de la branche par défaut), qui est aussi la dernière modification des trois scripts |
| Licence amont | MIT (`LICENSE` amont, © OpenCyphal) ; aucune mention de licence dans les scripts. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Partiel : `uavcan_can` (UAVCAN/CAN, en C) et `uavcan_dsdl` existent, mais ni Cyphal/UDP ni Cyphal v1.1 |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Les scripts sont repris tels quels (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/cyphal_1v1.lua` | Cyphal v1.1 : `set_plugin_info` (ligne 8), protocoles `cyphalcan11`, `cyphaludp11` et `cyphal11` (lignes 53 à 55), préférences de réassemblage (lignes 219 à 234), heuristiques `can` et `udp` (lignes 1710 et 1714), « Décoder comme » `can.subdissector` (lignes 1718 et 1719), port UDP 9382 et « Décoder comme » `udp.port` (lignes 1721 à 1724) |
| `src/cyphal_1v0_can.lua` | Cyphal/CAN v1.0 : protocole `cyphalcan` (ligne 28), « Décoder comme » `can.subdissector` seulement (lignes 245 et 246) ; décode Heartbeat et GetInfo |
| `src/cyphal_1v0_udp.lua` | Cyphal/UDP v1.0 : protocole `cyphaludp` (ligne 91), port UDP 9382 (lignes 87, 258 et 259) |

## Utilisation

Le README amont recommande `cyphal_1v1.lua` seul, avec Wireshark 4.6 ou
plus récent, et déconseille de le charger avec l'ancien dissecteur CAN.
Copier le ou les scripts voulus dans le dossier des plugins Lua
personnels (« Aide › À propos de Wireshark › Dossiers »), puis recharger
avec Ctrl+Maj+L.

- v1.1 : reconnu par heuristique sur CAN et UDP, et sur le port UDP 9382.
  Filtres : `cyphal11`, `cyphalcan11`, `cyphaludp11`.
- v1.0 CAN : « Décoder comme » › « CAN next level dissector » ›
  CYPHALCAN (`tshark -d can.subdissector,cyphalcan`). Filtre :
  `cyphalcan`.
- v1.0 UDP : port 9382. Filtre : `cyphaludp`.

## Vérification à l'import

`luac5.4 -p` : OK pour les trois scripts. tshark 4.6.4, scripts chargés
par `-X lua_script:` puis copiés dans le dossier des plugins : aucun
message au chargement. Le projet amont ne fournit pas de capture : sa
suite `tests/run.sh` génère des vecteurs avec deux programmes C
(`tests/generate_*_vectors.c`) et compare la sortie de tshark à des
fichiers de référence. Ces vecteurs, synthétiques, ne sont pas copiés.

| Essai | Résultat |
|---|---|
| Suite amont `tests/run.sh` (v1.1), avec les scripts importés de ce dossier | **OK** : sorties identiques aux fichiers de référence `expected-valid-can`, `expected-fragments-can`, `expected-invalid-can`, `expected-valid-udp` et `expected-invalid-udp` |
| v1.0 UDP, trame Heartbeat (sujet 7509) construite d'après la spécification | en-tête décodé, CRC16 et CRC32-C conformes aux valeurs calculées ; charge laissée en octets bruts |
| v1.0 UDP, requête et réponse de service 430 | `service_id: 430`, `request_not_response` correct |
| v1.0 UDP, trame de 2 octets | **erreur Lua** ligne 172 (`Range is out of bounds`) |
| v1.0 UDP sur les vecteurs v1.1 du port 9382 | décodés à tort en v1.0 (`version: 130`) ; une **erreur Lua** ligne 195 sur une trame invalide |
| v1.0 CAN, Heartbeat et requête GetInfo en SocketCAN, par « Décoder comme » | identifiants, sujet 7509, service 430, nœuds et octet de queue décodés ; Heartbeat détaillé (uptime, santé, mode) |
| v1.0 CAN, trame sans données | **erreur Lua** ligne 154 (`TreeItem_add: Malformed packet`) |
| v1.0 CAN sur les vecteurs CAN v1.1 | bits réservés signalés en avertissement ; erreurs Lua lignes 193 et 199 sur des trames GetInfo tronquées |
| Trois scripts ensemble dans le dossier des plugins | le port 9382 revient à `cyphal_1v1.lua` (chargé en dernier) : une trame v1.0 y est décodée à tort en « UDP1.1 » |

## Limites constatées

- Les scripts v1.0 et v1.1 réclament tous deux le port UDP 9382 : ne
  charger que l'un des deux à la fois, comme le conseille l'amont.
- `cyphal_1v0_udp.lua`, ligne 209 : `if not captured_crc16 ==
  computed_crc16` est toujours faux (priorité de `not`), si bien qu'un
  CRC16 d'en-tête faux n'est jamais signalé.
- `cyphal_1v0_udp.lua`, ligne 146 : faute de frappe
  `crc32_mismatch_export` dans la liste des experts (variable `nil`) ;
  le script déclare aussi de nombreuses variables globales.
- `cyphal_1v0_udp.lua` : la CRC32-C est vérifiée trame par trame, sans
  réassemblage des transferts sur plusieurs trames ; aucune vérification
  du numéro de version (des trames v1.1 sont décodées comme v1.0).
- Les scripts v1.0 ne vérifient pas la longueur des trames : erreurs Lua
  sur des trames courtes (voir le tableau).
- Le dissecteur natif `uavcan_can` reste prioritaire pour l'ancien
  UAVCAN ; `cyphal_1v0_can.lua` ne s'active que par « Décoder comme ».
