# Gizwits (protocole local des objets connectés Gizwits, PH-803W)

Dissecteurs Wireshark Lua du **protocole LAN Gizwits**, plateforme IoT
chinoise utilisée notamment par le contrôleur pH/ORP PH-803W : découverte
et onboarding en UDP 12414, échanges avec l'appareil en TCP 12416. Le
dissecteur principal décode l'en-tête (version, longueur variable, drapeaux,
commande) puis transmet les « data points » à des sous-dissecteurs par
produit, enregistrés dans une table `gizwits` indexée par `product_key`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Apollon77/node-ph803w (dossier `wireshark/`) |
| Commit importé | `ddf25e3e9a6e174a3144570cef2cd97c0645ff46` du 21/04/2024 (branche `main`, dernier commit ; dernière modification du dossier `wireshark/` : `698035e` du 23/10/2022) |
| Licence amont | MIT (`LICENSE` amont, © 2021-2024 Ingo Fischer) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Gizwits natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `gizwits.lua` | Dissecteur principal `gizwits` (UDP 12414, TCP 12416) ; crée la table `gizwits` |
| `gizwits_ph803w.lua` | Data points du PH-803W (« iMoniter », pH / ORP, relais) |
| `gizwits_clearlight.lua` | Data points d'un produit ClearLight |
| `gizwits_gizkit_soc_pet.lua` | Data points du kit de développement GizKit SOC (pet) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête de chaque fichier.

Non importés : `wireshark.lua` (fichier de déclarations `---@meta` pour
l'éditeur Lua — il redéfinit `base`, `ENC_*`… et fait `require "bit32"` ;
chargé par Wireshark, il écraserait les globales de l'API) et
`gizwits_template.lua` (modèle de génération avec `$product_key` non
renseigné).

## Utilisation

Copier les quatre fichiers `.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `gizwits`. `gizwits.lua` doit être chargé avant les fichiers
de data points (ordre alphabétique respecté : `gizwits.lua` précède
`gizwits_*.lua`).

## Remarques

- **`bit32` absent des Wireshark récents** : le décodage de la longueur
  variable (`gizwits.lua`) et des attributs booléens/énumérés (fichiers de
  data points) appelle `bit32.bor`, `bit32.band`, `bit32.lshift`,
  bibliothèque de Lua 5.2 absente par défaut de Lua 5.3 et 5.4, seules
  versions prises en charge depuis Wireshark 4.4 (qui fournit `bit` à la
  place). Contournement local : ajouter `bit32 = bit` en tête de
  `gizwits.lua` (code amont non modifié ici) ;
- les data points d'autres produits Gizwits s'ajoutent en générant un
  fichier à partir du modèle amont (`gizwits_template.lua`) et de l'API
  Gizwits (`/app/datapoint?product_key=…`) ;
- pas de capture d'exemple amont ; non vérifié dans Wireshark.
