# ESP-NOW (post-dissecteur, trames Wi-Fi Espressif)

Post-dissecteur Wireshark Lua de **ESP-NOW**, protocole sans connexion
d'Espressif (ESP8266 / ESP32) transporté dans des trames d'action 802.11
« vendor specific » : à partir du champ `data` laissé par Wireshark, il
décode les 4 octets aléatoires (anti-rejeu), l'élément vendeur (ID,
longueur, OUI Espressif 18:FE:34, type, version) et les données utiles.
Une préférence permet d'ignorer les paquets dont l'OUI n'est pas celui
d'Espressif.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/SoupySoups/ESPNOW-Wireshark-Dissector (fichier `espnow.lua`) |
| Commit importé | `142e7a7197f151102b0d275f08d68f40714f33b2` du 27/03/2025 (branche `main`, dernier commit ; dernière modification du dissecteur : `2d4eff5` du 27/03/2025) |
| Licence amont | GPL-2.0-only (README amont : « released under GNUv2 », sans « or later » ; `LICENSE` amont : texte de la GPL v2) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur ESP-NOW natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `espnow.lua` | Post-dissecteur `espnow`, préférence « Drop packets not signed Espressif OUI » ; fins de ligne CRLF d'origine conservées |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `espnow.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, ouvrir
une capture Wi-Fi en mode moniteur sur le canal des appareils, puis filtrer
avec `espnow`.

## Remarques

- **Colonnes écrasées sur tous les paquets** : la fonction affecte
  « ESP-NOW » aux colonnes Protocole et Info avant de vérifier la présence
  d'un champ `data` ; une fois le plugin chargé, toutes les trames de la
  capture peuvent afficher « ESP-NOW » dans la liste (le filtre `espnow`
  reste fiable). À ne charger que pour des captures ESP-NOW.
- **`bit32` absent des Wireshark récents** : la séparation version /
  réservé appelle `bit32.band` et `bit32.rshift`, bibliothèque de Lua 5.2
  absente par défaut de Lua 5.3 et 5.4, seules versions prises en charge
  depuis Wireshark 4.4 (qui fournit `bit` à la place). Contournement local :
  ajouter `bit32 = bit` en tête du fichier (code amont non modifié ici).
- Variable globale `espnow_postdissector` comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
