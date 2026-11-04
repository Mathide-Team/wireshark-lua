# CoAP « coap18 » (dissecteur Lua historique)

Dissecteur Wireshark Lua **historique** (2014-2016) du protocole **CoAP**
(Constrained Application Protocol, RFC 7252 — alias draft 18) avec les
extensions **Observe** (RFC 7641) et **transfert par blocs** (draft 18) :
en-tête (version, type CON/NON/ACK/RST, longueur du jeton, code, ID de
message), jeton, options (Uri-Path, Uri-Query, Content-Format, Observe,
Block1/Block2, ETag, Max-Age…) et charge utile, sur UDP 5683. Il expose de
nombreux champs filtrables sous le préfixe `coap18.*`
(ex. `coap18.options.uripath == "test"`).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/okleine/coap-lua (fichier `coap18.lua`) |
| Commit importé | `f2869947cdd09f7b1f8a8fbbde37070ad5b4060c` du 12/04/2016 (branche `master`, dernier commit ; dernière modification du dissecteur : `9bfa872` du 12/04/2016) |
| Licence amont | BSD-3-Clause — texte de la licence BSD à 3 clauses en en-tête du fichier (« Copyright (c) 2014, Oliver Kleine, Institute of Telematics, University of Luebeck »), conservé ; pas de fichier LICENSE dans le dépôt |
| Natif Wireshark 4.6.4 | **Oui** — dissecteur natif `coap` (RFC 7252, Observe, Block, OSCORE, CoAP sur TCP/TLS/WebSocket…) ; ce script Lua est à considérer comme obsolète ou pédagogique |

Le texte de la licence est celui de l'en-tête du fichier `coap18.lua`
(aucun fichier `LICENSE` séparé n'existe en amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `coap18.lua` | Protocole `coap18` (UDP 5683) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `coap18.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `coap18`. Dans la plupart des cas, le dissecteur natif `coap`
suffit.

## Remarques

- **Remplace le dissecteur CoAP natif sur UDP 5683** une fois chargé
  (`udp.port` 5683 réattribué à `coap18`).
- **`bit32` absent des Wireshark récents** : le décodage de la longueur du
  jeton et des options appelle `bit32.band` et `bit32.rshift`, bibliothèque
  de Lua 5.2 absente par défaut de Lua 5.3 et 5.4, seules versions prises en
  charge depuis Wireshark 4.4 (qui fournit `bit` à la place). Sans `bit32`
  global, la dissection échoue dès le premier paquet ; contournement local :
  ajouter `bit32 = bit` en tête du fichier (code amont non modifié ici).
- Variables globales `coapProto` et `udp_table` comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
