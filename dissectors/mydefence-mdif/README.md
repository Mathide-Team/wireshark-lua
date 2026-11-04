# MDIF — MyDefence Device Interface

Dissecteur Wireshark Lua de **MDIF**, l'interface de programmation des
équipements de **MyDefence** (composants cœur, mise à jour
micrologicielle, capteur RF « RFS » à algorithmes de détection,
effecteur RF « RFE »), lorsque les messages passent par
Ethernet. Protocole `mdif` sur TCP : trames préfixées par une longueur sur
4 octets (petit-boutiste), réassemblage TCP, puis lecture du numéro de
champ protobuf du message pour choisir le type racine et passage au
dissecteur **Protobuf natif** de Wireshark avec les fichiers `.proto`
fournis.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/mydefence/mdif (fichier `src/wireshark/create_mdif_dissector.lua` et définitions `src/protobuf/mdif/`) |
| Commit importé | `d97ac10122669b18530e25225692076477b5e1f6` du 13/10/2026 (branche `main`, dernier commit ; dernière modification du script : `10f85b9` du 16/11/2023) |
| Licence amont | Apache-2.0 (fichier `LICENSE` amont, copié ici ; en-têtes des `.proto` : « Copyright 2023 MyDefence A/S » — 2024 pour `rfe.proto` — « Licensed under the Apache License, Version 2.0 ») ; le script Lua n'a pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non (le dissecteur Protobuf générique est natif et utilisé par le script) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `create_mdif_dissector.lua` | Protocole `mdif` (TCP), appelle le dissecteur `protobuf` |
| `protobuf/mdif/common.proto` | Types communs (`mdif.common`) |
| `protobuf/mdif/core/core.proto` | Messages `mdif.core.CoreMsg` |
| `protobuf/mdif/fwu/fwu.proto` | Mise à jour micrologicielle, `mdif.fwu.FwuMsg` |
| `protobuf/mdif/rfs/rfs.proto` | Capteur RF, `mdif.rfs.RfsMsg` |
| `protobuf/mdif/rfe/rfe.proto` | Effecteur RF, `mdif.rfe.RfeMsg` |
| `LICENSE` | Licence Apache 2.0 amont |

Le script est importé tel quel (seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée) ; les `.proto` sont copiés sans
modification.

## Utilisation

D'après la documentation amont (`docs/wireshark.html`) :

1. copier `create_mdif_dissector.lua` dans le dossier des plugins Lua
   personnels ;
2. dans Préférences → Protocols → ProtoBuf, ajouter aux chemins de
   recherche le dossier `protobuf/` (celui qui contient `mdif/`) ;
3. « Décoder comme… » le port TCP 21020 en `MDIF` (le script ne
   s'enregistre que sur le port 0 de `tcp.port`, uniquement pour
   apparaître dans ce menu).

Filtrer ensuite avec `mdif` ou les champs `pbf.mdif.*` du dissecteur
Protobuf.

## Remarques

- **Correspondance incomplète des types** : le script n'associe que les
  numéros de champ < 0x20 à `mdif.core.CoreMsg`, < 0x30 à
  `mdif.fwu.FwuMsg` et < 0x50 à `mdif.core_dev.CoreDevMsg` — ce dernier
  type n'existe dans aucun `.proto` fourni. Les messages RFS (champs à
  partir de 0x80) et RFE (à partir de 0xC0) ne sont pas associés ; comme
  la variable `msgtype` n'est pas réinitialisée entre les paquets, ils
  risquent d'être décodés avec le dernier type utilisé. De plus, les
  messages `CoreMsg` vont jusqu'au numéro 257 et ne sont donc pas tous
  reconnus.
- `get_tag` est une fonction globale ; le champ `MDIF.length` porte un
  préfixe en majuscules.
- `rfs.proto` importe `google/protobuf/timestamp.proto`, non fourni :
  il doit être trouvable dans les chemins de recherche Protobuf (par
  exemple le dossier `include` d'une installation de protobuf).
- Seul le transport TCP est géré (pas le lien série HDLC décrit par
  l'amont).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
