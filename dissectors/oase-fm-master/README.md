# Oase FM Master — prises pilotées de bassin et jardin

Dissecteur Wireshark Lua du **protocole UDP des contrôleurs Oase FM
Master** (prises commandées pour pompes, éclairages et variateur de
bassin) : chaîne magique `\#OA`, longueur des données, numéro de
séquence, sens (vers le contrôleur `0x00` / depuis le contrôleur `0xff`),
code de commande, données brutes, et décodage des commandes `0xc4`
(pilotage d'une prise : index et intensité / marche-arrêt) et `0xc5`
(état des cinq sorties). Port UDP 5959.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/wwwenca/oase-wireshark |
| Commit importé | `3f06e536b9c84a07b54d48f03f021476adf8b5e6` du 04/04/2022 (branche `main`, dernier commit ; dernière modification de `oase.lua` : `9f4eac3` du 04/04/2022) |
| Licence amont | BSD-2-Clause (`LICENSE` amont, © 2022 wwwenca) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Oase natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `oase.lua` | Protocole `oase` sur UDP 5959 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `oase.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `oase`. Champs filtrables : `oase.command`,
`oase.direction`, `oase.sequence`…

## Remarques

- Le champ `oase.details` (`generated_details`) n'est **pas déclaré**
  dans `proto_oase.fields` ; les Wireshark récents refusent l'ajout d'un
  champ non enregistré, ce qui peut produire une erreur Lua dans l'arbre
  pour les commandes `0xc4` / `0xc5`. Contournement local : ajouter
  `generated_details` à la liste `proto_oase.fields` (code amont non
  modifié ici).
- Le README amont décrit le format des trames (rétro-ingénierie).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
