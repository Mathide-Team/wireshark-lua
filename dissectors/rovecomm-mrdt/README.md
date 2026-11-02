# RoveComm — protocole des rovers de la Mars Rover Design Team (MRDT)

Dissecteur Wireshark Lua du protocole RoveComm de la Mars Rover Design
Team (Missouri S&T), utilisé entre les cartes électroniques de ses rovers
martiens de compétition et le poste de commande. Il décode l'en-tête de
6 octets (version, `dataId`, `dataCount`, `dataType`), nomme le message
d'après le manifeste RoveComm (139 messages de commande, télémétrie et
erreur, plus 6 paquets système), décode les valeurs selon le type
(entiers 8 à 32 bits, flottants, caractères) et signale les écarts avec
le manifeste par des alertes expertes (issue #780).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/MissouriMRDT/RoveCommWiresharkDissector (`rovecomm.lua`) |
| Commit importé | `5c8994242e7d3be2125cfd3eba8ae7853b6eacb8` du 24/02/2026 (dernier commit de la branche par défaut, « Update RoveComm manifest version ») ; c'est aussi la dernière modification de `rovecomm.lua` |
| Licence amont | GPL-3.0 (`LICENSE` amont, texte de la GNU GPL version 3) ; aucune mention dans le script ni dans le README, sans clause « ou toute version ultérieure », d'où l'identifiant SPDX `GPL-3.0-only`. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur RoveComm dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

`rovecomm.lua` est le fichier **généré** et commité par l'amont : le
script `compile.py` y écrit des tables tirées du manifeste
`RoveComm_Base/manifest.json` (sous-module
[MissouriMRDT/RoveComm_Base](https://github.com/MissouriMRDT/RoveComm_Base),
commit `654f00f18827e021ce83411c4d591bd35c07e8ba` au commit importé),
puis y recopie `source.lua`. Seul le fichier généré, directement
utilisable, est importé ; `compile.py` et `source.lua` ne le sont pas.
Pour suivre une autre version du manifeste, il faut régénérer le fichier
avec l'outil amont.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/rovecomm.lua` | Tables générées (lignes 6 à 742 : noms et tailles des types, paquets système, adresses IP, noms, types, nombres et commentaires de chaque `dataId`) ; protocole `rovecomm` (« Mars Rover Design Team RoveComm », ligne 759) ; champs `rove.*` (lignes 761 à 773) ; alertes expertes (lignes 774 à 810) ; dissecteur ligne 812 ; ports TCP 12000 (ligne 865) et UDP 11000 (ligne 868) |

## Utilisation

Copier `src/rovecomm.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`). Le trafic des ports UDP 11000 et
TCP 12000 est décodé. Filtres : `rovecomm`, `rove.data_id`,
`rove.data_count`, `rove.data_type`, et un champ par type de valeur
(`rove.FLOAT_T`, `rove.UINT8_T`…).

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : chargement sans erreur. Le
dépôt amont ne contient aucune capture. Essais sur des captures
synthétiques (version 3), non commitées :

| Essai (UDP 11000) | Résultat |
|---|---|
| `dataId` 3000, 2 × `FLOAT_T` (0,5 ; −0,25) | « 3000 (Core.Commands.DriveLeftRight) », `FLOAT_T: 0.5`, `FLOAT_T: -0.25`, sans alerte |
| `dataId` 1, `dataCount` 0 | « 1 (PING) », `data: <MISSING>` |
| `dataId` 9999 inconnu | « Unknown » et alerte « The encoded data_id does not exist in the manifest » |
| `dataType` 12 | « Unknown », erreur experte « The data_type does not exist in the manifest », données confiées au dissecteur `data` |
| `dataId` 3000 avec 1 × `UINT8_T` | valeur décodée, alertes d'écart de nombre (« (2) ») et de type (« (6 FLOAT_T) ») avec le manifeste |
| `dataCount` 3 pour 8 octets de flottants | **erreur Lua** ligne 842 (« Range is out of bounds ») après les deux premières valeurs : l'alerte de longueur n'est jamais atteinte |
| Paquet de 5 octets | **erreur Lua** ligne 827 (« Range is out of bounds ») |
| Filtres | `rovecomm` : 7 paquets ; `rove.data_id == 3000` : 4 ; `rove.FLOAT_T == 0.5` : 1 |

| Essai (TCP 12000) | Résultat |
|---|---|
| Deux messages (DriveLeftRight puis PING) dans un même segment | un seul message décodé ; les 6 octets du PING sont ajoutés aux données du premier, avec l'alerte « The encoded data_count does not equal the actual length » |

## Limites constatées

- Le contrôle de longueur minimale (ligne 813) accepte 5 octets alors
  que l'en-tête en fait 6 : erreur Lua sur un paquet de 5 octets.
- La boucle des valeurs (lignes 841 à 843) lit `dataCount` valeurs sans
  vérifier la longueur : erreur Lua quand le paquet est tronqué, au lieu
  de l'alerte prévue (ligne 844).
- En TCP, aucun découpage des messages ni réassemblage : seul le premier
  message d'un segment est décodé.
- Les tailles de types sont générées sous forme de chaînes (`"4"`,
  lignes 18 à 28) ; Lua les convertit à l'usage, sans effet constaté.
- Les tables reflètent le manifeste à la date du commit importé ; les
  adresses IP (table `IPS`) sont générées mais pas utilisées.
- Variables globales : `rove_protocol`, `version_field`,
  `data_id_field`, `data_count_field`, `data_type_field`, `data_field`.
