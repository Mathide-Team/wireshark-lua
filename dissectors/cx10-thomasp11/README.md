# Cheerson CX-10DS — commandes de vol du quadricoptère (thomasp11)

Dissecteur Wireshark Lua du protocole de commande du mini-quadricoptère
Cheerson CX-10DS (version Wi-Fi du CX-10). L'application mobile envoie au
drone, en UDP sur le port 8033, des trames courtes qui contiennent le
roulis, le tangage, les gaz, le lacet, une commande (décollage,
atterrissage, looping, étalonnage) et une somme de contrôle (issue #546).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/thomasp11/CX-10-Wireshark (`CX-10.lua`) |
| Commit importé | `f76437a24836ac0b1a07b2cfaa9f2313dab642cb` du 08/08/2017 (dernier commit de la branche par défaut), qui est aussi la dernière modification du script |
| Licence amont | MIT (`LICENSE` amont, © 2017 Thomas Peterson) ; aucune mention de licence dans le script. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur CX-10 dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/CX-10.lua` | Protocole `cx-10ds` (« CX-10DS Drone Protocol », ligne 9), champs `cs10ds.roll`, `.pitch`, `.throttle`, `.yaw`, `.command` et `.checksum` (lignes 10 à 15), dissecteur ligne 18 ; inscrit sur le port UDP 8033 (ligne 47) |

## Utilisation

Copier `src/CX-10.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis recharger
avec Ctrl+Maj+L. Les trames sont reconnues sur le port UDP 8033 ; pour
un autre port, « Décoder comme » › CX-10DS. Filtres : `cx-10ds`,
`cs10ds.throttle`, `cs10ds.command == "takeoff"` (les champs sont en
`cs10ds.*`, pas en `cx10ds.*`).

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement. Le
dépôt amont ne contient aucune capture. Essais sur une capture
synthétique de trames de 8 octets (octet `0x66`, quatre axes,
commande, somme de contrôle, octet `0x99`), non commitée :

| Essai | Résultat |
|---|---|
| Axes au neutre, gaz à 0, commande 0 | « Roll: 128 », « Pitch: 128 », « Throttle: 0 », « Yaw: 128 », « Command: none » |
| Commandes 1, 2, 64 et 128 | « takeoff », « land », « flip », « calibrate » |
| Commande inconnue (3) | « none » |
| Axes variés (100, 150, 200, 90) | valeurs exactes |
| Filtre `cs10ds.command == "takeoff"` | une trame sélectionnée |
| Trame de 3 octets | **erreur Lua** ligne 26 (`Range is out of bounds`) |

## Limites constatées

- La longueur n'est pas vérifiée : une trame de moins de 7 octets
  provoque une erreur Lua (ligne 26 dans l'essai).
- Seuls les octets 1 à 6 sont lus : l'octet 0 et les octets au-delà du
  septième ne sont pas affichés. La somme de contrôle (octet 6) n'est pas
  vérifiée.
- Le champ `cs10ds.command` est une chaîne ajoutée sans plage d'octets
  (ligne 41) : il n'est pas relié à l'octet de commande, et une
  combinaison de bits (par exemple décollage + étalonnage) s'affiche
  « none ».
- Les noms de champs utilisent le préfixe `cs10ds` alors que le
  protocole s'appelle `cx-10ds` ; `cx10ds_proto` et `udp_table` sont des
  variables globales.
- Pas d'heuristique : seul le port UDP 8033 est reconnu, et le sens
  drone → application (vidéo, télémétrie) n'est pas décodé.
