# CoAP sur DTLS (heuristique sur le trafic DTLS déchiffré)

Petit dissecteur heuristique Wireshark Lua qui fait décoder **en CoAP toute
charge DTLS déchiffrée**, quel que soit le port : il s'enregistre comme
heuristique du protocole `dtls` et passe la charge au dissecteur CoAP natif
de Wireshark. Utile pour les objets connectés (LwM2M, OSCORE…) qui parlent
CoAPS sur un port non standard, une fois les clés DTLS (PSK ou fichier de
clés) fournies à Wireshark.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/msangoi/dtls-coap-dissector (fichier `dtls-coap-hdissector.lua`) |
| Commit importé | `f1d033f64251179629d5b35b052aa1fff60d5c00` du 03/11/2016 (branche `master`, dernier commit, qui modifie aussi le dissecteur) |
| Licence amont | MIT (`LICENSE` amont, © 2016 Manuel Sangoï) |
| Natif Wireshark 4.6.4 | En partie — le dissecteur CoAP natif (`packet-coap.c`) décode déjà CoAP sur DTLS, mais seulement sur le port 5684 (`dtls_dissector_add(5684, …)`) ; ce script étend cela à tous les ports |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `dtls-coap-hdissector.lua` | Protocole `coaps` : heuristique `dtls` → dissecteur `coap` natif (10 lignes) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `dtls-coap-hdissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer
`wireshark -X lua_script:dtls-coap-hdissector.lua -r capture.pcap`,
renseigner les clés DTLS (Préférences → Protocoles → DTLS), puis filtrer
avec `coap`.

## Remarques

- **Heuristique sans condition** : la fonction renvoie toujours `true`, donc
  toute charge DTLS déchiffrée non attribuée est affichée en CoAP, même s'il
  s'agit d'un autre protocole. Ne charger ce script que pour des captures
  CoAPS.
- Globales `h_dissector` et `coaps_proto` comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
