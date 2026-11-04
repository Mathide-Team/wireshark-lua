# Space CoAP — CoAP adapté au Bundle Protocol (réseaux spatiaux DTN)

Dissecteur Wireshark Lua **« Space CoAP »**, variante expérimentale de
CoAP conçue pour fonctionner sur le Bundle Protocol (réseaux tolérants
aux délais, DTN) dans un travail de recherche de l'UPC (groupe ENTEL-WNG) :
en-tête CoAP avec **identifiant de message sur 24 bits** (au lieu de
16), jeton, options CoAP habituelles (Uri-Path, Content-Format, Observe,
Block…) plus une option **Payload-Length**, et charge utile. Ports UDP
5683 et 5684, plus une heuristique UDP.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ENTEL-WNG/CoAPoverBP-no-proxy-version |
| Commit importé | `a2fb4311b89b31c30e93a5c1704f78131594e927` du 12/06/2025 (branche `main`, dernier commit ; dernière modification de `spacecoap.lua` : `f7ce233` du 06/05/2025) |
| Licence amont | AGPL-3.0-or-later (`LICENSE` AGPL v3 ; en-tête : « either version 3 of the License, or any later version », © 2025 Michael Karpov) |
| Natif Wireshark 4.6.4 | Non pour Space CoAP ; CoAP standard natif (`coap`) |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont). La GPLv3 du dépôt permet la combinaison avec du
code AGPLv3 (article 13) ; précédents : `dissectors/aerospike/`,
`dissectors/donet/`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `spacecoap.lua` | Protocole `spacecoap` sur UDP 5683 / 5684 et heuristique UDP |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le reste du dépôt (aiocoap et µD3TN
modifiés, scripts d'expérience) n'est pas importé.

## Utilisation

Copier `spacecoap.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou, de préférence, le charger
ponctuellement avec `wireshark -X lua_script:spacecoap.lua capture.pcap`,
puis filtrer avec `spacecoap`.

## Remarques

- **Remplace CoAP standard** : le script prend les ports UDP 5683 et
  5684, où le CoAP natif (16 bits d'identifiant) sera alors mal décodé.
- **Heuristique très large** : elle accepte tout datagramme UDP de plus
  de 5 octets dont le premier octet commence par les bits `01` (version
  CoAP 1), ce qui peut faire décoder à tort une grande partie du trafic
  UDP. Désactivable dans Analyse › Protocoles heuristiques
  (`spacecoap_udp`).
- L'auteur le qualifie de « hautement expérimental ».
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
