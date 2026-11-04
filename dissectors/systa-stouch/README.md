# Paradigma SystaComfort — protocole S-Touch

Dissecteur Wireshark Lua du **protocole « device touch » de l'application
S-Touch**, qui pilote à distance l'écran tactile des régulateurs de
chauffage **Paradigma SystaComfort** (via l'interface SystaTouch) sur
UDP 3477 : type de paquet, commande, identifiant de paquet, sous-type,
puis contenu des commandes (appuis à l'écran avec coordonnées, commandes
de dessin de l'écran distant, réponses OK / ERR…).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/beep-projects/SystaPi (fichier `helpers/stouch.lua`) |
| Commit importé | `827b95b51a3cfff2068cc9fd284985cc62851b46` du 03/04/2026 (branche `main`, dernier commit ; dernière modification du dissecteur : `dbb9d80` du 22/04/2025) |
| Licence amont | GPL-3.0-or-later (en-tête du fichier : « Copyright (c) 2021, The beep-projects contributors », « either version 3 of the License, or (at your option) any later version » ; `LICENSE` amont : GPL v3) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur S-Touch / SystaComfort natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `stouch.lua` | Dissecteur `S-Touch` (UDP 3477), champs `S-Touch.*` |

Fichier importé tel quel, à une exception près : seule une en-tête SPDX +
provenance a été ajoutée en tête, plus une **correction locale minimale**.
Le fichier amont ne compile pas (opérateur `||`, qui n'existe pas en Lua,
ligne 86 amont : Wireshark refuserait de charger le script) ; il est
remplacé par `or`, et la correction est décrite dans l'en-tête du
fichier. Le reste est identique à l'amont.

## Utilisation

Copier `stouch.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, capturer
le trafic entre l'application S-Touch (ou le service `STouchREST` de
SystaPi) et la SystaComfort, puis filtrer avec `s-touch`.

## Remarques

- Nom de protocole et préfixe de champs avec majuscules et tiret
  (`S-Touch`) : acceptation par Wireshark 4.6 et nom exact du filtre non
  vérifiés.
- Nombreuses variables globales (champs `packet_type`, `pressX`…) comme
  dans l'amont, susceptibles d'entrer en collision avec d'autres scripts.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
