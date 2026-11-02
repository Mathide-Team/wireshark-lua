# CANaerospace (ubx)

Dissecteur Wireshark Lua du protocole CANaerospace, couche applicative
légère pour bus CAN en avionique (Stock Flight Systems, spécification
1.7). Pour chaque trame CAN, il décode l'identifiant de paramètre
(table de 585 identifiants normalisés, 300 à 1800), l'identifiant de
nœud, le type de données, le code de service et le code de message,
puis la valeur, convertie selon son type (FLOAT, LONG, SHORT, etc.) et
son unité (issue #533).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ubx/CANaerospace-Wireshark-plugin (`src/canas-protocol.lua`, `src/utils.lua`) |
| Commit importé | `76adc5158f85dba77ca5505cd785eb3e47fc52e3` du 21/07/2026 (dernier commit de `master`, dernière modification de `utils.lua`) ; dernière modification de `canas-protocol.lua` : commit `baff5f8be9da966967186e3fe222005e09c2bf56` du 01/01/2026 |
| Licence amont | GPL-3.0-or-later (en-tête « SPDX-License-Identifier: GPL-3.0-or-later » des deux fichiers, © 2019 Andreas Lüthi ; `LICENSE` amont : texte de la GPLv3). Identique à la licence de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur CANaerospace dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Les scripts sont repris tels quels (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête de chacun (convention du dépôt, issue #563). Les
en-têtes d'origine, avec leur propre ligne SPDX, suivent cette en-tête.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/canas-protocol.lua` | Protocole `canas` (« CANaerospace Protocol », ligne 38), `set_plugin_info` (ligne 23) ; chargement de `utils` par `require` (ligne 31). Il s'inscrit sur `sll.ltype` 12 (ligne 130), en « Décoder comme » sur `can.subdissector` (ligne 137) et sur `can.id` pour chaque identifiant de la table (ligne 149). Il tente aussi `wtap_encap` (lignes 159 et 164) |
| `src/utils.lua` | Décodage des valeurs (`utils.getValue`, ligne 453), unités par identifiant (ligne 122), tables des identifiants (ligne 459), des nœuds (ligne 1052), des types de données et des codes de service |

## Utilisation

Copier les deux fichiers de `src/` ensemble dans le dossier des plugins
Lua personnels de Wireshark (« Aide › À propos de Wireshark ›
Dossiers »), puis recharger avec Ctrl+Maj+L, ou lancer `wireshark -X
lua_script:src/canas-protocol.lua`. Le script ajoute son propre dossier
au `package.path` pour trouver `utils.lua`. Ouvrir ensuite une capture
SocketCAN (`candump`, pcap de type `LINKTYPE_CAN_SOCKETCAN`). Filtres :
`canas`, `canas.canid == 315`, `canas.nodeid`, `canas.datatype`.

## Vérification à l'import

`luac5.4 -p` : OK pour les deux scripts. tshark 4.6.4, chargés par `-X
lua_script:` (depuis un autre dossier de travail), puis copiés dans le
dossier des plugins : aucun message au chargement. Capture synthétique
SocketCAN (type de lien 227) construite d'après la spécification :

| Essai | Résultat |
|---|---|
| ID 315, nœud 10, FLOAT 61,5 | « Indicated Airspeed », « Node ID: GPS (10) », « Data Type: FLOAT (2) », « Data: 61.500 m/s (221.400 km/h) » |
| ID 300, FLOAT −1,25 | « Body Longitudinal Acceleration », « Data: -1.25 m/s2 » |
| ID 311, SHORT −12 | « Body Pitch Angle », « Data: -12 deg » |
| ID 1500, ULONG 42 | « ISU Sensor board temperature », « Data: 42 K » |
| ID 302, DLC 2 (en-tête CANaerospace incomplet) | seul « CAN ID » est affiché, sans erreur |
| ID 128 (service de nœud, hors table) | non décodé : reste en CAN |

## Limites constatées

- L'inscription se fait par identifiant (`can.id`), et seulement pour
  ceux de la table (300 à 1800). Les services de nœud (NSH, identifiants
  128 à 199), les identifiants définis par l'utilisateur et les autres
  plages restent en CAN brut, sauf avec « Décoder comme » sur
  `can.subdissector`.
- Le chemin « trame CAN complète » (16 octets ou plus, ligne 60)
  suppose l'en-tête SocketCAN ; non vérifié sur `sll.ltype` 12.
- Le type de données est lu tel quel ; les types non gérés par
  `utils.lua` (« WIP: to be extended » amont) sont affichés en octets
  bruts.
- Le code de message et la valeur ne sont pas des champs filtrables.
- Pas de capture réelle dans le dépôt amont (seule une copie d'écran,
  non reprise).
