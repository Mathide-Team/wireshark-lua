# ARINC 429 et signaux discrets (Airbus CyberSecurity)

Deux dissecteurs Wireshark Lua d'Airbus CyberSecurity pour les captures
avioniques au format PCAPNG (issue #539) :

- `a429` décode le mot ARINC 429 de 32 bits sur la couche de liaison 147
  (`USER_DLT0`) : label en octal, avec ses bits inversés, SDI, SSM,
  données sur 19 bits et parité ;
- `discrete` décode la valeur d'un signal discret sur la couche de
  liaison 148 (`USER_DLT1`).

Dans les deux cas, le nom du canal suit la valeur. C'est une chaîne
terminée par un octet nul, placée dans la colonne Source.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/airbus-cyber/Aeronautical-Wireshark-Plugin (`cyber_a429.lua`, `cyber_discrete.lua`, `pcapng_files/`) |
| Commit importé | `6185ec4519dd50890bffe15973ac5b89a0f19344` du 09/01/2025 (dernier commit de `main`) ; dernière modification des scripts, des captures et des licences : commit `e309db5d7cb5e8ae120f2c47dbf9e8ac2585ef09` du 26/03/2024 |
| Licence amont | GPL-3.0-or-later. L'en-tête de chaque script, le `LICENSE` amont et le README amont portent tous « either version 3 of the License, or (at your option) any later version », © 2023 Airbus CyberSecurity SAS. `COPYING` amont contient le texte de la GPLv3. GitHub affiche « NOASSERTION » faute de reconnaître le `LICENSE` court. Identique à la licence de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur ARINC 429 ni discret dans `tshark -G protocols` (seul `a615a`, ARINC 615A, sans rapport) |

Textes de licence : `COPYING` (GPLv3) et `LICENSE` (avis de licence),
copies conformes des fichiers amont. Les scripts sont repris tels quels
(aucune modification de code) ; seule l'en-tête de provenance de cinq
lignes est ajoutée en tête de chacun (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/cyber_a429.lua` | Protocole `a429` (« ARINC 429 », ligne 23), champs `A429.WORD`, `A429.LABEL`, `A429.SDI`, `A429.SSM`, `A429.DATA`, `A429.PARITY` ; dissecteur ligne 87 |
| `src/cyber_discrete.lua` | Protocole `discrete` (« DISCRETE », ligne 23), champ `DISCRETE.VALUE` ; dissecteur ligne 54 |
| `captures/arinc429_broadcast.pcapng` | Capture amont `pcapng_files/arinc429_broadcast.pcapng` (140 octets, 2 mots ARINC 429, canal « RX3 », USER 0) |
| `captures/discrete.pcapng` | Capture amont `pcapng_files/discrete.pcapng` (212 octets, 3 valeurs discrètes, canal « DS1 », USER 1) |

## Utilisation

Copier les deux scripts de `src/` dans le dossier des plugins Lua
personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »).
Il faut ensuite associer les couches de liaison utilisateur, soit dans
« Préférences › Protocols › DLT_USER » (`User 0 (DLT=147)` → `a429`,
`User 1 (DLT=148)` → `discrete`), soit avec le fichier `user_dlts` du
dépôt amont, soit en ligne de commande :

```
tshark -o 'uat:user_dlts:"User 0 (DLT=147)","a429","0","","0",""' \
       -o 'uat:user_dlts:"User 1 (DLT=148)","discrete","0","","0",""' \
       -r captures/arinc429_broadcast.pcapng
```

Filtres : `a429`, `A429.LABEL == 0136`, `discrete`, `DISCRETE.VALUE`.

## Vérification à l'import

`luac5.4 -p` : OK pour les deux scripts. tshark 4.6.4, chargés par `-X
lua_script:`, puis copiés dans le dossier des plugins, avec l'association
DLT 147/148 : aucun message au chargement. Le README amont annonce
pourtant Wireshark < 4.3 et Lua 5.2 : le `require("bit")` de la ligne 50
de `cyber_a429.lua` trouve la bibliothèque BitOp intégrée à Wireshark.

| Essai | Résultat |
|---|---|
| `captures/arinc429_broadcast.pcapng` | 2 mots décodés, Source « RX3 » ; sortie `-T fields` identique à `test/a429_broadcast.output` amont (labels 94 et 35, mots `0x4700007a` et `0xc80001c4`, SDI, SSM, données, parité) |
| `captures/discrete.pcapng` | 3 valeurs décodées, Source « DS1 » ; sortie identique à `test/discrete.output` amont (`0x00000000`, `0x00000001`, `0x00000001`) |
| Capture synthétique DLT 147 : mot seul (4 octets) et mot suivi de « RX1 » sans octet nul | mot décodé, colonne Source vide |
| Capture synthétique DLT 147 : 2 octets | **erreur Lua** ligne 83 de `cyber_a429.lua`, ou ligne 49 de `cyber_discrete.lua` quand les deux scripts sont chargés (`Range is out of bounds`) |

## Limites constatées

- Les deux scripts définissent les mêmes fonctions globales
  (`_get_string_length`, `_set_source_column_value`). Le second chargé
  remplace celles du premier. Elles sont équivalentes, donc sans effet
  visible, mais les erreurs sont alors signalées dans l'autre fichier.
  Les champs `WORD`, `LABEL`, `VALUE`, etc. sont aussi globaux.
- Pas de contrôle de longueur : une trame de moins de 4 octets provoque
  une erreur Lua.
- Le nom du canal n'est pris que s'il se termine par un octet nul.
- Le label et les champs sont décodés, mais les données ne sont pas
  interprétées selon le label (pas de table d'équipements ni d'unités
  BNR/BCD).
- Sans l'association DLT 147/148, rien n'est décodé.
