# AMX Device Discovery — balises de découverte des équipements AMX

Dissecteur Wireshark Lua des **balises AMX Device Discovery (AMX
Beacon)**, émises en UDP par les contrôleurs et équipements AMX
(Harman) d'automatisation audiovisuelle et domotique : trame texte
`AMXB<-SDKClass=…><-UUID=…><-Make=…><-Model=…>…` terminée par un retour
chariot, décodée en paires nom / valeur (classe, identifiant, fabricant,
modèle, révision, URL de configuration…), avec les valeurs reprises dans
la colonne Info. Port UDP 9131.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/hisasan/amxdd-dissector |
| Commit importé | `df867fd0311b35e331d0be75e532b2c43a7fb7fb` du 06/02/2020 (branche `master`, dernier commit, qui est aussi la dernière modification de `amxdd.lua`) |
| Licence amont | MIT (`LICENSE` amont, © 2017 Hisanobu Doi) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur AMX Beacon natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont, fins de ligne CRLF).

## Fichiers

| Fichier | Rôle |
|---|---|
| `amxdd.lua` | Protocole `amxdd` sur UDP 9131 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `amxdd.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `amxdd`.

## Remarques

- Seules les balises sont décodées (comme l'indique le README amont) ;
  les paires nom / valeur sont des éléments texte, non filtrables
  individuellement.
- Variable globale `amxdd` et nom de protocole en majuscules, comme dans
  l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
