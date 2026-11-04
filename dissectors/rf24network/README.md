# RF24Network (radio nRF24L01+, passerelle RF24Gateway)

Dissecteur Wireshark Lua des **messages RF24Network** relayés par la
passerelle Linux **RF24Gateway** entre des nœuds Arduino à modules radio
nRF24L01+ et le réseau IP : en-tête RF24Network (nœud maillé, nœuds
source et destination en octal, identifiant, type, taille de charge utile)
et lecture des premiers octets de la charge utile en entiers 16/32 bits.
Les messages sont vus sur UDP 32001 sur la machine qui fait tourner la
passerelle.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/nRF24/RF24Gateway (fichier `examples/addons/RF24Network.lua`) |
| Commit importé | `f81b281acad1cc840f7390faae95309d4edf36b3` du 30/10/2026 (branche par défaut, dernier commit ; dernière modification du dissecteur : `b3ddc43` du 31/03/2021) |
| Licence amont | GPL-2.0-only (`LICENSE` amont : texte de la GPL v2, sans mention « or any later version » ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur RF24Network natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `RF24Network.lua` | Dissecteur `rf24network` (UDP 32001), champs `rf24network.*` |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Sur la machine qui exécute RF24Gateway : copier `RF24Network.lua` dans le
dossier `plugins` de Wireshark (ex. `~/.local/lib/wireshark/plugins/`) ou
lancer `wireshark -X lua_script:RF24Network.lua`, puis appliquer le filtre
`!icmp` (consigne amont) ou `rf24network`.

## Remarques

- La ligne « Data(HEX) » utilise une variable `pSize` non définie (globale
  `nil`) : l'intervalle couvre alors toute la fin du tampon ; laissé tel
  quel (non vérifié dans Wireshark).
- Le décodage de la charge utile se limite aux 2 ou 4 premiers octets.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
