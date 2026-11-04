# Fujitsu AirStage-H / Halcyon (bus série des climatiseurs Fujitsu)

Dissecteurs Wireshark Lua du **bus série AirStage-H (Halcyon) de Fujitsu
General**, qui relie unités intérieures, télécommandes filaires et
contrôleurs de zones des climatiseurs gainables Fujitsu. Les trames série
sont capturées par un ESP32 sous ESPHome
([esphome-tzspserial](https://github.com/Omniflux/esphome-tzspserial)) et
envoyées à Wireshark encapsulées en TZSP sur UDP 37008 : adresse source /
destination, type de trame, mode de fonctionnement, consigne, ventilation,
oscillation, températures (contrôleur, capteur déporté), filtre, codes
d'erreur, fonctions et zones, avec détection des trames dupliquées.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Omniflux/fujitsu-airstage-h-dissector |
| Commit importé | `abbbf404a9dc609c610c82b6e87a8292991ccb82` du 20/09/2026 (branche `main`, dernier commit, qui modifie aussi les deux dissecteurs) |
| Licence amont | MIT (`LICENSE` amont, © 2023 Omni Flux) |
| Natif Wireshark 4.6.4 | Non — TZSP est natif, pas le bus Fujitsu |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `dissector-fujitsuair.lua` | Dissecteur `fujitsuair` : bus AirStage-H (TZSP encapsulation 255) |
| `dissector-fujitsuair-dmmum.lua` | Dissecteur `fujitsuair-dmmum` : variante des contrôleurs multi-unités UTY-DMMUM (TZSP encapsulation 254) |
| `wireshark-coloring-rules.txt` | Règles de coloration amont (commentaires, trames dupliquées) |
| `protocol-notes.txt` | Notes amont sur le protocole |
| `captures/*.pcapng` | 10 captures d'exemple amont (fonctionnement normal, essais, sonde déportée, filtre, zones, erreur J5.7…) |
| `captures/*.txt` | 2 traces texte amont (appuis de boutons, programmation de zones) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête des fichiers Lua. Non importés : la capture
`1683777646.pcapng` (1,6 Mo, au-delà de la limite de 1 Mo) et le script
`esphome_log_parser.py`.

## Utilisation

Copier les deux fichiers `.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
faire « Décoder comme… » UDP 37008 → TZSP (README amont) et filtrer avec
`fujitsuair || fujitsuair-dmmum`. Les règles de coloration s'importent dans
Affichage → Règles de coloration → Importer.

## Remarques

- Dissecteur « incomplet » selon l'auteur : plusieurs champs restent
  inconnus.
- Les valeurs d'encapsulation TZSP 254 / 255 sont des valeurs privées
  choisies par esphome-tzspserial.
- Utilise la bibliothèque `bit` (fournie par Wireshark), pas `bit32`.
- Non vérifié dans Wireshark (pas de tshark dans l'environnement de test).
