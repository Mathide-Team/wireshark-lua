# SAPIENT — BSI Flex 335 v2.0 (gestion de capteurs, lutte anti-drones)

Dissecteur Wireshark Lua des messages **SAPIENT** au format BSI Flex 335
version 2.0 (« SAPIENT sCUAS », interface de gestion de capteurs), par
Jean Vanhay (version 2.0). Protocole `sapientmessages` : chaque message
est précédé d'une longueur sur 4 octets (petit-boutiste) ; le corps est
passé au dissecteur **Protobuf natif** comme
`sapient_msg.bsi_flex_335_v2_0.SapientMessage`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Hellikandra/SapientWireshark (fichier `plugins/sapient_protobuf_dissector.lua`) |
| Commit importé | `468787629572ac4c955f890b60daa6ff2fe7c92d` du 14/09/2024 (branche `main`, dernier commit ; dernière modification du script : `cd08789` du 14/09/2024) |
| Licence amont | MIT d'après le script (`set_plugin_info` : `license = "MIT license"`, auteur Jean Vanhay), retenue ici ; le dépôt a toutefois un fichier `LICENSE` Apache 2.0 (copié ici). Les deux licences sont permissives |
| Natif Wireshark 4.6.4 | Non (le dissecteur Protobuf générique est natif et utilisé par le script) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `sapient_protobuf_dissector.lua` | Protocole `sapientmessages` (« Décoder comme… » TCP/UDP) |
| `LICENSE` | Fichier de licence du dépôt amont (Apache 2.0) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Les copies amont de
`google/protobuf/descriptor.proto` et `timestamp.proto` ne sont pas
reprises ; les `.proto` SAPIENT ne sont pas non plus dans le dépôt amont.

## Utilisation

1. Copier le script dans le dossier des plugins Lua personnels.
2. Récupérer les fichiers `.proto` SAPIENT
   (https://github.com/dstl/SAPIENT-Proto-Files) et les fichiers
   Protobuf standard de Google, puis ajouter leurs dossiers aux chemins
   de recherche Protobuf (Préférences → Protocols → ProtoBuf).
3. « Décoder comme… » le port TCP utilisé en `SapientMessages` (le script
   ne s'enregistre que sur le port 0 de `tcp.port` et `udp.port`).

Pour une autre version de SAPIENT, modifier le type passé à
`create_sapient_protobuf_dissector` en fin de script (conseil amont).

## Remarques

- **Défauts amont relevés à la lecture** (messages découpés sur plusieurs
  segments TCP) :
  - le script écrit dans `sapient_msg.is_partial_message`, variable qui
    n'existe pas (au lieu de `sapient_state`) : une erreur Lua est
    probable dès qu'un message dépasse le segment courant ;
  - la longueur demandée pour le réassemblage est calculée par
    `msg_len - (header - remaining_len)` au lieu de
    `msg_len - (remaining_len - header)`, et l'offset de réassemblage
    saute l'en-tête ;
  - l'état de réassemblage est partagé entre toutes les conversations.
  Les messages contenus dans un seul segment ne sont pas concernés.
- Le script affiche de nombreux messages de débogage (`print`) à chaque
  paquet.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
