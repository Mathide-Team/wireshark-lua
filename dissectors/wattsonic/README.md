# Wattsonic (onduleurs hybrides solaires)

Dissecteur Wireshark Lua des **paquets de télémétrie envoyés par les
onduleurs hybrides Wattsonic** vers leurs serveurs cloud, sur TCP 5743 :
numéro de série, date, état de santé et de charge de la batterie, durée de
fonctionnement, températures de l'onduleur et du pack BMS, et autres
valeurs à positions fixes (sans chiffrement, un paquet par minute selon
l'amont).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/schoerg/wattsonic |
| Commit importé | `b23b660a3f18370791404ae1dea57ca3c0d0be36` du 06/08/2023 (branche `master`, dernier commit) |
| Licence amont | GPL-3.0-only (`LICENSE` amont : texte de la GPL v3, sans mention « or any later version » ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Wattsonic natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `wattsonic.lua` | Dissecteur `wattsonic` (TCP 5743), champs `wattsonic.*` |
| `captures/wattsonic.pcap` | Capture d'exemple amont (`doc/wattsonic.pcap`) |

Fichier Lua importé tel quel ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête. La capture est une copie binaire
conforme.

## Utilisation

Copier `wattsonic.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, ouvrir
`captures/wattsonic.pcap` (ou une capture faite sur un port miroir / le
routeur) et filtrer avec `wattsonic`.

## Remarques

- Positions des champs trouvées par l'auteur en comparant avec les réponses
  Modbus ; les paquets de 58 octets ne sont pas analysés (amont).
- Non repris : la documentation constructeur du protocole Modbus (PDF,
  droits non précisés) et la capture d'écran — disponibles dans le dépôt
  amont.
- Non vérifié dans Wireshark, y compris sur la capture fournie.
