# RoverLink (BYU Mars Rover)

Ébauche de dissecteur Wireshark Lua du protocole RoverLink. Ce protocole
de messages a été défini en 2014 par l'équipe Mars Rover de la Brigham
Young University (BYU), d'après MAVLink, dans `RoverLink.xml`. Le script
déclare le protocole et décode seulement les deux premiers octets de la
charge TCP (« Command ») ; les textes affichés sont des marques
provisoires du modèle d'origine (issue #537).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/StephenCarlson/BYU-Mars-Rover (`roverlink.lua`) |
| Commit importé | `83b37cdb4fc11466ffa53586aefd1828319c0dcf` du 21/11/2014 (dernier commit de `master`, unique commit du script) |
| Licence amont | GPLv2 (fichier `LICENSE` du dépôt, sans clause « or later » hors de l'annexe modèle de la licence ; le script ne porte aucune mention de licence) — auteur : Stephen Carlson. Déclarée `GPL-2.0-only` comme pour `dissectors/avionique` |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur RoverLink dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code, fins de ligne CRLF d'origine conservées) ; seule
l'en-tête de provenance de cinq lignes est ajoutée en tête (convention du
dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/roverlink.lua` | Protocole `roverlink` (« BYU RoverLink », ligne 6), champ `roverlink.command` (uint16 hexadécimal) ; inscrit sur TCP 8002 (ligne 36) |

## Utilisation

Copier `src/roverlink.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis recharger
avec Ctrl+Maj+L. Les lignes 38 à 40 (chemin Windows de l'auteur avec
`dofile` dans `init.lua`) sont inutiles avec le dossier des plugins.
Filtres : `roverlink`, `roverlink.command`.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement.
Capture synthétique TCP 40000 → 8002 :

| Essai | Résultat |
|---|---|
| Segment de 5 octets `01 23 61 62 63` | « BYU RoverLink, Command details here or in the tree below », « Command: 0x0123 [Command text] » |
| Segment de 1 octet | **erreur Lua** ligne 21 (`Range is out of bounds`) |

## Limites constatées

- Le script n'est qu'un modèle : aucun message de `RoverLink.xml` n'est
  décodé (ni en-tête, ni identifiant, ni charge utile). Les textes
  « [Command text] » et « Command details here… » sont des marques
  provisoires.
- `RoverLink.xml` décrit un protocole UDP, alors que le script s'inscrit
  sur TCP 8002. Pour UDP, il faut utiliser « Décoder comme… ».
- Le champ `roverlink.data` (ligne 8) est déclaré avec `FT_STRING`, variable non
  définie en Lua (donc `nil`), et n'est jamais utilisé.
- Les variables `subtree` et `dissector` sont globales (lignes 19 et 33).
  La seconde écrase le nom d'une éventuelle variable globale d'un autre
  script.
- Pas de contrôle de longueur : un segment de moins de 2 octets
  provoque une erreur Lua. Pas de réassemblage TCP.
- Pas de capture réelle dans le dépôt amont.
