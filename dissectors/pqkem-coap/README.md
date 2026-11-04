# PQ-KEM sur CoAP (échange de clés post-quantique pour objets connectés)

Post-dissecteur Wireshark Lua d'un **protocole expérimental d'échange de
clés post-quantique (ML-KEM-512 / Kyber) sur CoAP**, issu d'un projet de
recherche sur microcontrôleurs PineCone / BL602 : il ne remplace pas le
dissecteur CoAP natif, mais repère le trafic UDP 5683, saute l'en-tête et
les options CoAP, puis ajoute un sous-arbre « PQKEM over CoAP » décodant les
petites structures du projet — KEM_REQ (algorithme, longueur et texte
chiffré KEM), KEM_RESP et DATA (nonce de 12 octets, charge AES-CCM et tag
de 16 octets).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ChanduKomme/Post-quantum-key-exchange-mechanisms-for-IoT-devices (fichier `sniffer/sniffer/wireshark_pqkem_coap.lua`) |
| Commit importé | `9dca83b74e1a64268c2f8b47a928e6d313991c81` du 30/10/2026 (branche `master`, dernier commit ; dernière modification du dissecteur : `b986009` du 15/03/2026) |
| Licence amont | MIT — déclarée par l'auteur dans le README (badge « License: MIT » renvoyant vers https://opensource.org/licenses/MIT) ; pas de fichier LICENSE à la racine ni d'en-tête de licence dans le fichier Lua (les fichiers `LICENSE` du dépôt ne concernent que la bibliothèque tierce `kyber512_ref`) |
| Natif Wireshark 4.6.4 | Non — CoAP est natif, mais pas ce format applicatif propre au projet |

L'amont ne fournit pas de texte de licence : texte de référence de la
licence MIT : https://spdx.org/licenses/MIT.html — à reproduire avec la
mention « Copyright (c) ChanduKomme » (titulaire du dépôt) en cas de
redistribution.

## Fichiers

| Fichier | Rôle |
|---|---|
| `wireshark_pqkem_coap.lua` | Post-dissecteur `pqkem` (UDP 5683) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier. Le reste du dépôt (firmwares
émetteur / récepteur / renifleur BL602, bibliothèque Kyber) n'est pas
importé.

## Utilisation

Copier `wireshark_pqkem_coap.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `pqkem`.

## Remarques

- Format propre au prototype de recherche : sans intérêt hors de ce projet.
- Post-dissecteur : appelé sur chaque paquet, il ne garde que le port 5683.
- Utilise la bibliothèque `bit` (fournie par Wireshark), pas `bit32`.
- Le README amont signale un identifiant Wi-Fi codé en dur dans le firmware
  du renifleur (non importé ici) ; rien de sensible dans le fichier Lua.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
