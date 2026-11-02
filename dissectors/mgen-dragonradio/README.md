# MGEN — messages du générateur de trafic (DragonRadio, Drexel)

Dissecteur Wireshark Lua des messages MGEN (« Multi-Generator »), le
générateur de trafic de test de l'U.S. Naval Research Laboratory,
employé par DragonRadio, la radio logicielle de l'université Drexel
(compétition DARPA SC2). Le script décode l'en-tête MGEN : taille,
version, drapeaux, flux, numéro de séquence, heure d'émission, adresses
de destination et d'hôte, position GPS, charge utile, bourrage et somme
de contrôle. Il connaît aussi la variante DARPA (version 4), avec un
champ réservé et un octet TOS (priorité, classe) (issue #773).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/drexelwireless/dragonradio (`tools/wireshark/mgen_dissector.lua`) |
| Commit importé | `da3808d267b54995a6ef95f317c66d1d1b4f22a9` du 22/11/2021 (dernier commit de la branche par défaut) ; dernière modification du script : commit `9da786a43443280fae15d05a317db2341361a0e9` du 10/08/2019 |
| Licence amont | MIT (`LICENSE` amont, © 2017-2020 Drexel University) ; aucune mention de licence dans le script. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur MGEN dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/mgen_dissector.lua` | Protocole `mgen` (« MGEN Protocol », ligne 6), champs `mgen.*` (lignes 12 à 146) ; préférences « Port number » (5001) et « Heuristic enabled » (lignes 152 à 182) ; dissecteur ligne 210 ; port UDP 5001 (ligne 333) et heuristique `udp` (lignes 335 à 359) |

## Utilisation

Copier `src/mgen_dissector.lua` dans le dossier des plugins Lua
personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »),
puis recharger avec Ctrl+Maj+L. Les messages sont reconnus sur le port
UDP 5001, modifiable dans « Préférences › Protocoles › MGEN ». Filtres :
`mgen`, `mgen.flow_id`, `mgen.seq`, `mgen.flags.checksum`, `mgen.tos`.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement. Le
dépôt amont ne contient aucune capture. Essais sur des captures
synthétiques construites d'après le format décrit par le script et par
la [documentation MGEN](https://github.com/USNavalResearchLaboratory/mgen/blob/master/doc/mgen.html)
(coordonnées codées `(valeur + 180) × 60000`), non commitées :

| Essai | Résultat |
|---|---|
| Version 2, latitude 48.8156, longitude 7.7905 | en-tête, drapeaux, flux, séquence, heure, adresses 10.0.0.2:5001 et 10.0.0.1:40000 décodés, puis **erreur Lua** ligne 299 (`number has no integer representation`) : le reste du message n'est pas affiché |
| Mêmes messages, sans arbre (`tshark -r` sans `-V`) | **tshark s'arrête** une fois sur deux en fin de lecture (`except.c:270: except_pop: Assertion … failed`, code 134), en `-X lua_script:` comme en dossier de plugins ; pas observé avec `-V` |
| Version 2, coordonnées entières (48 et 7) | décodé jusqu'au bout ; les valeurs s'affichent inversées (« Longitude: 48 », « Latitude: 7 ») ; altitude 150, « GPS status: Current (2) » |
| Charge utile de 5 octets et 10 octets de bourrage | « Payload: 68656c6c6f », « Padding length: 10 » |
| Somme de contrôle (drapeau `0x04`) | « Checksum: 0xdeadbeef », bourrage calculé sans les 4 derniers octets |
| Version 4 (DARPA), TOS `0x52` | « Reserved », « TOS: 0x52 », « Priority: 5 », priorité calculée « 1.5125 » |
| Message de 8 octets | arbre MGEN vide, octets en « Data » |
| Message MGEN valide sur le port UDP 6000 (heuristique) | ni MGEN ni Data : le datagramme est revendiqué mais rien n'est affiché |

## Limites constatées

- Lignes 299 et 303 : la longitude et la latitude converties en degrés
  (nombres décimaux) sont ajoutées à des champs `uint32` (lignes 85
  et 86). Sous Wireshark 4.6, toute position non entière provoque une
  erreur Lua et coupe la dissection ; dans le mode sans arbre, tshark
  peut même s'arrêter sur une assertion.
- Le script lit la longitude avant la latitude (lignes 298 à 304), alors
  que la documentation MGEN décrit la latitude en premier : les deux
  valeurs s'affichent inversées.
- L'heuristique (lignes 335 à 356) renvoie seulement vrai ou faux sans
  appeler le dissecteur : un message reconnu hors du port 5001 disparaît
  de l'arbre.
- Les champs lus par `Field.new` (lignes 188 à 200) et appelés comme
  fonctions (par exemple ligne 239) supposent la présence de l'arbre.
  `base.Dec` (lignes 58, 63 et 88) n'existe pas (c'est `base.DEC`).
  `off`, `version`, `priority` et d'autres sont des variables globales.
- La priorité TOS (ligne 287) n'est pas arrondie (1.5125 au lieu de 1.5).
  Les adresses IPv6 ne sont pas affichées (seulement sautées). Les
  messages fragmentés ne sont pas réassemblés et la somme de contrôle
  n'est pas vérifiée.
