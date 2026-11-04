# TP-Link Tapo (protocole propriétaire des caméras Tapo)

Dissecteur Wireshark Lua du **protocole propriétaire des caméras IP TP-Link
Tapo** (testé par l'auteur sur une Tapo C100) :

- **découverte d'appareils** sur UDP 20002 / 20004 : en-tête de 16 octets
  (version, type, code d'opération, longueur, drapeaux, numéro de série,
  somme de contrôle) puis charge JSON (passée au dissecteur JSON natif) ou
  binaire ;
- **contrôle et flux média** sur TCP 8800 : messages multipart de type
  HTTP (frontière de flux, `Content-Type`, `Content-Length`,
  `X-Session-Id`, indicateur de chiffrement), avec charge chiffrée
  signalée, le HTTP classique restant transmis au dissecteur HTTP ;
- **maintien de connexion** sur le port 8001.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/KostasEreksonas/Tapo_protocol_analysis (fichier `tapoWireshark.lua`) |
| Commit importé | `3666da95d0ffca3df6e945a224a70972067bb643` du 31/08/2026 (branche `main`, dernier commit ; dernière modification du dissecteur : `130a769` du 19/07/2026) |
| Licence amont | GPL-3.0-or-later (en-tête du fichier : « Copyright (C) 2026 Kostas Ereksonas », « either version 3 of the License, or (at your option) any later version » ; `LICENSE` amont : texte de la GPL v3) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Tapo natif (le `tplink-smarthome` natif concerne les prises Kasa, protocole différent) |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `tapoWireshark.lua` | Dissecteur `tapo` (UDP 20002, 20004, 8001 ; TCP 8800) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier. Non importés : les schémas et
captures d'écran `images/` du README amont, qui documente aussi en détail
la structure des paquets.

## Utilisation

Copier `tapoWireshark.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `tapo` (champs `tapo.opcode`, `tapo.serial_number`,
`tapo.session_id`…).

## Remarques

- Travail en cours selon l'auteur (« WIP ») ; testé sur un seul modèle.
- Le port 8001 est enregistré en **UDP** dans le code, alors que le README
  amont parle de TCP 8001 pour le maintien de connexion (non vérifié).
- Les flux média chiffrés ne sont pas déchiffrés.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
