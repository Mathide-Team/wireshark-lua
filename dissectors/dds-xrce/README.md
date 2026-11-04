# DDS-XRCE (DDS pour environnements très contraints, Micro-XRCE-DDS)

Dissecteur Wireshark Lua du protocole **DDS-XRCE** (OMG « DDS for
eXtremely Resource Constrained Environments »), en particulier de son
implémentation eProsima **Micro-XRCE-DDS** utilisée par micro-ROS sur
microcontrôleurs : en-tête de message (session, flux, numéro de séquence,
clé client), sous-messages CREATE_CLIENT, CREATE, GET_INFO, DELETE,
STATUS_AGENT, STATUS, INFO, WRITE_DATA, READ_DATA, DATA, ACKNACK,
HEARTBEAT, RESET, FRAGMENT, TIMESTAMP…, avec suivi optionnel des objets
DDS (topics, datareaders, datawriters) et désérialisation XCDR des types
utilisateurs enregistrés. Transports UDP et TCP (port 2018 par défaut,
configurable dans les préférences), et découverte d'agent.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/jseldent/wireshark-dds-xrce |
| Commit importé | `b3d212522dddac1955cdd569d464049a36b8e309` du 15/02/2023 (branche `main`, dernier commit) |
| Licence amont | Apache-2.0 (`LICENSE` amont ; en-tête Apache 2.0 « Copyright 2022 Lely Industries N.V. » dans chaque fichier, conservée) |
| Natif Wireshark 4.6.4 | Non — Wireshark dissèque nativement RTPS (DDS « complet », `packet-rtps.c`), mais pas DDS-XRCE |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `dds-xrce-proto.lua` | Dissecteur `DDS-XRCE` (UDP/TCP, préférences de ports, découverte) ; fait `require "dds-xrce-types"` |
| `dds-xrce-types.lua` | Désérialisation des types DDS-XRCE ; fait `require "dds-xrce-idl"` |
| `dds-xrce-idl.lua` | Primitives IDL/XCDR et tables globales `types`, `topic_type_names`… pour les types utilisateurs |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête de chaque fichier. Non importée : la capture
d'écran `PublishHelloWorld.png` (pointeur Git LFS dans le dépôt amont).

## Utilisation

Copier les trois fichiers dans `~/.local/lib/wireshark/plugins/` (dossier
présent dans le `package.path` Lua de Wireshark, nécessaire aux `require`),
redémarrer Wireshark, puis filtrer avec `dds-xrce`. Le port 2018 se change
dans Préférences → Protocoles → DDS-XRCE.

Pour décoder un type utilisateur, ajouter un fichier Lua qui fait
`require "dds-xrce-idl"` et enregistre une fonction dans `types["MonType"]`
(exemple `HelloWorld` détaillé dans le README amont).

## Remarques

- Requiert Wireshark ≥ 3.5 (`assert` sur `redissect_packets`).
- La désérialisation des types utilisateurs suppose qu'un seul client est
  connecté à l'agent et que la création des entités DDS a été capturée
  (README amont).
- Les modules `require`-és sont aussi chargés comme plugins par Wireshark ;
  ils ne définissent que des fonctions et tables (pas de protocole), ce
  double chargement est celui prévu par l'amont (non vérifié dans Wireshark).
- Pas de capture d'exemple amont.
