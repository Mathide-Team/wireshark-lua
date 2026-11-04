# TIN-AAA — protocole maison d'un mandataire pour réseau de capteurs

Dissecteur Wireshark Lua du **protocole « AAA » du projet étudiant TINs**
(mandataire HTTP pour un réseau de capteurs simulé, 2021) : en-tête de
2 octets — type de paquet (DATA, ACK, ERROR, sur les 2 bits de poids fort), numéro de paquet (ou
code d'erreur : mauvais type, mauvaise session, mauvais compteur) et
identifiant de session — puis charge utile texte. Port UDP 3000.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/amasiukevich/TINs (fichier `src/wireshark/tin-aaa.lua`) |
| Commit importé | `d80a64891ecd0cf64d5d04f715e2dfc00dae908d` du 10/06/2021 (branche `main`, dernier commit ; dernière modification du script : `03fbea5` du 07/06/2021) |
| Licence amont | MIT (`LICENSE` amont, © 2021 Anton Masiukevich, Joanna Sokołowska, Adrian Brodzik) |
| Natif Wireshark 4.6.4 | Non — protocole propre au projet |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `tin-aaa.lua` | Protocole `aaa` sur UDP 3000 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le reste du dépôt (mandataire, appareils
simulés en C++, sous-modules) n'est pas importé.

## Utilisation

Copier `tin-aaa.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`, inutile de lancer Wireshark en
`sudo` comme dans le README amont), recharger les plugins Lua, puis
filtrer avec `aaa`.

## Remarques

- **Noms de champs génériques** : les champs sont déclarés sous les
  abréviations `type`, `num` et `session`, sans préfixe de protocole, ce
  qui peut entrer en conflit avec d'autres champs ou être refusé par les
  Wireshark récents ; arguments de `ProtoField.uint8/uint16` décalés
  (`base.dec` en minuscules vaut `nil`). Laissé tel quel.
- Le nom de protocole court et générique `aaa` peut prêter à confusion
  avec l'authentification / autorisation / comptabilité (Diameter,
  RADIUS) : il s'agit ici d'un protocole d'exercice.
- Le port UDP 3000 est souvent utilisé par d'autres applications.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
