# Pentair ScreenLogic — automatisation de piscine

Dissecteur Wireshark Lua du **protocole ScreenLogic de Pentair**
(passerelle réseau des automates de piscine et spa) : connexion,
défi / réponse, authentification, horloge, version, configuration du
contrôleur, état (températures, pompes, circuits, chloration au sel),
équipements, plannings… Chaque type de message est décodé par un
sous-protocole enregistré dans une table de dissecteurs `pentair`.
Port TCP 80.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/EdDuran/WireShark-ScreenLogic-Dissector |
| Commit importé | `032e1dc3e39ec579c25da10539ecc87cc4df7260` du 24/05/2023 (branche `main`, dernier commit, qui est aussi la dernière modification de `screenlogic.lua`) |
| Licence amont | GPL-3.0-only (`LICENSE` GPL v3 ; aucune mention « or later » dans le fichier ni le README ; en-tête du script : Keith Roberts, v1.0.0.0 du 24/05/2023) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Pentair natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `screenlogic.lua` | Protocole `pentair` (et sous-protocoles `pentair.*`) sur TCP 80 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `screenlogic.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `pentair`.

## Remarques

- **Prend le port TCP 80** : tant que le script est chargé, le trafic
  HTTP sur ce port est décodé comme ScreenLogic. À ne charger que pour
  analyser une passerelle ScreenLogic (ou changer le port localement).
- Le champ `Pentair.Password` affiche le mot de passe de connexion
  transmis : attention avant de partager une capture.
- Utilise `bit.band` (bibliothèque `bit` fournie par Wireshark 4.4 et
  plus) ; noms de protocoles et de champs avec majuscules, variables
  globales, comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
