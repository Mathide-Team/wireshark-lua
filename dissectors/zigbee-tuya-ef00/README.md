# Zigbee ZCL 0xEF00 (cluster privé Tuya)

Dissecteur Wireshark Lua du **cluster Zigbee 0xEF00**, cluster privé
utilisé par les appareils **Tuya** (thermostats, vannes, capteurs,
rideaux… vendus sous de nombreuses marques) pour transporter leurs « data
points » : commande, statut, identifiant de transaction, numéro de data
point, type de donnée (RAW, BOOL, VALUE, STRING, ENUM, FAULT), fonction,
longueur et valeur décodée selon le type.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/pekkasaastamoinen/wireshark_zcl_ef00_dissector (fichier `zcl_ef00.lua`) |
| Commit importé | `0190c3e1a7e049cfc0e4c70eddb9dda616933545` du 28/03/2024 (branche `main`, dernier commit, qui modifie aussi le dissecteur) |
| Licence amont | GPL-2.0-only (en-tête du fichier : « Copyright (C) 2024 psaastam@iki.fi — License: GNU General Public License v2.0 only » ; `LICENSE` amont : texte de la GPL v2) |
| Natif Wireshark 4.6.4 | Non — Zigbee ZCL est natif et connaît le code fabricant Tuya (0x125D), mais pas le contenu du cluster 0xEF00 |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `zcl_ef00.lua` | Protocole `zcl_ef00`, enregistré dans la table `zbee.zcl.cluster` pour 0xEF00 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `zcl_ef00.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, ouvrir
une capture Zigbee (avec la clé réseau renseignée dans les préférences
Zigbee pour déchiffrer la couche NWK/APS), puis filtrer avec `zcl_ef00`.

## Remarques

- Testé par l'auteur uniquement avec un appareil n'envoyant que des types
  VALUE et ENUM, sous Wireshark 3.6.2 (README amont).
- La signification de chaque numéro de data point dépend du modèle Tuya et
  n'est pas décodée.
- Variable globale `zcl_ef00_protocol` comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark 4.6.
