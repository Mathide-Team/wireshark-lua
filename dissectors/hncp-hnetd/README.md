# HNCP — Home Networking Control Protocol (hnetd)

Dissecteur Wireshark Lua **basique** du **Home Networking Control
Protocol** (HNCP, RFC 7788, au-dessus de DNCP, RFC 7787), protocole de
configuration automatique des réseaux domestiques multi-routeurs (IETF
Homenet), tel qu'implémenté par le démon `hnetd` d'OpenWrt : décodage
récursif des TLV sur UDP 8231 (demandes d'état réseau / nœud, état de
nœud, hachages, identifiants de lien, numéro de mise à jour, keep-alive,
délégation et attribution de préfixes, etc. — une vingtaine de types
nommés).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/sbyx/hnetd (fichier `hnetd_wireshark.lua`) |
| Commit importé | `c43766610ed30194b048bc070a3c433aec731c40` du 21/12/2018 (branche `master`, dernier commit ; dernière modification du dissecteur : `4e7d49b` du 14/07/2018) |
| Licence amont | Apache-2.0 (`LICENSE` amont ; en-tête du fichier : « Author: Markus Stenberg », « Copyright (c) 2013 cisco Systems, Inc. ») |
| Natif Wireshark 4.6.4 | Non — pas de `packet-hncp.c` dans la branche `release-4.6` (vérifié dans l'arborescence des sources Wireshark le 01/11/2026) |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont). Pas de fichier `NOTICE` amont.

## Fichiers

| Fichier | Rôle |
|---|---|
| `hnetd_wireshark.lua` | Dissecteur `hncp` (UDP 8231), champs `hncp.*` |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier. Les fichiers Lua LuCI du dépôt
amont (interface web OpenWrt) ne sont pas des dissecteurs et ne sont pas
repris.

## Utilisation

Copier `hnetd_wireshark.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer
`wireshark -X lua_script:hnetd_wireshark.lua`, puis filtrer avec `hncp`.

## Remarques

- Dissecteur « TRÈS basique » selon son auteur : seules les TLV transmises
  par hnetd sont nommées ; les autres sont affichées en données brutes.
- Les échanges HNCP sécurisés par DTLS (UDP 8232) ne sont pas décodés.
- Variables globales (`p_hncp`, `udp_table`) comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
