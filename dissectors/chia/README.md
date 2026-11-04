# Chia — protocole pair-à-pair de la blockchain Chia

Dissecteur Wireshark Lua du protocole réseau binaire de **Chia** (version
du script 2.5.1.dev1) : protocole `chia` — en-tête de message (type,
identifiant optionnel, longueur) et désérialisation détaillée des charges
utiles pour 105 types de messages (1 à 107, plus 255 `error`) des
composants nœud complet, portefeuille, farmer, harvester et timelord.
Les pairs Chia échangent ces messages dans des WebSocket sécurisées : le
script s'enregistre dans la table native `ws.port` (ports 8000, 8444, 8447
et 58444) et nécessite donc le déchiffrement TLS.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/10etennba/chia-wireshark-dissector-lua (fichier `chia.lua`) |
| Commit importé | `cf48287ddbdf3c25e1e173024fec24d340ca4227` du 15/02/2025 (branche `main`, dernier commit ; dernière modification du script : `897787b` du 15/02/2025) |
| Licence amont | GPL-3.0-or-later (en-tête du script : « either version 3 of the License, or (at your option) any later version », Copyright (C) 2025 10etennba ; fichier `LICENSE` amont GPLv3, copié ici) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Chia natif (WebSocket et TLS sont natifs) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `chia.lua` | Protocole `chia` sur WebSocket, ports 8000, 8444, 8447, 58444 |
| `LICENSE` | Licence GPLv3 amont |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le fichier amont `chia.lua.sha256sum` n'est
pas repris : il ne correspond plus au script après ajout de l'en-tête.

## Utilisation

Copier `chia.lua` dans le dossier `plugins` de Wireshark. Le trafic Chia
étant chiffré, il faut un fichier de clés TLS (`SSLKEYLOGFILE`), que le
logiciel Chia officiel ne produit pas sans modification de son code
(`server.py`, procédure détaillée dans le README amont), et capturer la
poignée de main TLS. Indiquer ce fichier dans Préférences → Protocols →
TLS, puis filtrer avec `chia`.

## Remarques

- La variable `SHOW_SERIAL_PROTO` (valeur `false`) en tête du
  script affiche, si on la passe à `true`, les champs de sérialisation
  (longueurs, indicateurs d'option).
- Défaut amont relevé à la lecture : la fonction locale `error` (message de
  type 255) attend `(tvb, offset, data_range, data_tree)` mais est appelée
  avec trois arguments `(tvb, offset, data_tree)` ; `data_tree` y vaut
  alors `nil`, ce qui devrait provoquer une erreur Lua sur ces messages.
  Cette fonction masque aussi la fonction standard `error` dans la suite du
  fichier.
- Le protocole `p_chia` est une variable globale ; l'enregistrement dans
  `ws.port` se fait dans la fonction `init` (à chaque rechargement).
- D'après le README amont, le test de tous les types de messages est
  encore en cours. Pas de capture d'exemple amont ; non vérifié dans
  Wireshark.
