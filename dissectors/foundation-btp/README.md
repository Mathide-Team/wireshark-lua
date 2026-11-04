# BTP — Beefcake Transfer Protocol (Foundation Devices, BLE)

Dissecteur Wireshark Lua du **Beefcake Transfer Protocol** (BTP) de
Foundation Devices, qui découpe les messages GSTP de l'API
d'appareil à appareil en morceaux adaptés à la MTU Bluetooth Low Energy.
Post-dissecteur `btp_proto` : il repère dans le paquet une écriture ATT
sans réponse (opcode 0x52, handle 0x0010) ou une notification (opcode
0x1b, handle 0x0012), puis décode l'en-tête BTP de 8 octets (identifiant
de message, index du morceau, nombre total de morceaux, longueur utile,
octet de bourrage) et affiche les données du morceau en hexadécimal, avec
trois alertes expertes (bourrage non nul, index ≥ total, longueur
supérieure aux données disponibles).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Foundation-Devices/foundation-api (fichier `btp/wireshark_dissector/btp.lua`) |
| Commit importé | `aba3b33e6b038b664f0df8672ab069c8966b9a6b` du 14/08/2026 (branche `main`, dernier commit ; dernière modification du script : `921c433` du 16/01/2026) |
| Licence amont | GPLv3 déclarée dans le README amont (« This project is licensed under the GPLv3 License. »), sans mention « or later », d'où `GPL-3.0-only` ; pas de fichier `LICENSE` amont ni d'en-tête dans le script — le texte de la GPLv3 est fourni ici dans `LICENSE` |
| Natif Wireshark 4.6.4 | Non (ATT / L2CAP Bluetooth sont natifs) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `btp.lua` | Post-dissecteur `btp_proto` (champs `btp.*`) |
| `LICENSE` | Texte de la GPLv3 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `btp.lua` dans le dossier `plugins` de Wireshark, ouvrir une capture
BLE contenant le trafic entre appareils Foundation, puis filtrer avec
`btp_proto` ou `btp.message_id`.

## Remarques

- Les handles ATT 0x0010 et 0x0012 sont codés en dur : ils dépendent de la
  table GATT de l'appareil.
- Post-dissecteur sans filtre préalable : la recherche des octets
  opcode + handle se fait sur chaque paquet, même hors BLE, d'où des faux
  positifs possibles.
- Le script lit `fi.tvb` sur le champ `btl2cap` ; l'API FieldInfo
  documentée de Wireshark expose `source` et `range`, pas `tvb` : cette
  ligne risque de provoquer une erreur Lua dès qu'un champ L2CAP est
  présent (non vérifié).
- Pas de réassemblage des morceaux BTP ni de décodage GSTP. Pas de capture
  d'exemple amont ; non vérifié dans Wireshark.
