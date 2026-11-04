# OpenWebNet — passerelles domotiques Legrand / BTicino MyHOME

Dissecteur Wireshark Lua du protocole **OpenWebNet** (OWN), protocole
texte des passerelles domotiques Legrand / BTicino MyHOME
(trames `*WHO*WHAT*WHERE##`) : ouverture de session (commande ou
événements), authentification (nonce, mot de passe OPEN, HMAC), ACK / NACK,
commandes normales, demandes d'état, demandes et écritures de grandeurs
(WHO, WHAT, WHERE, dimension, valeurs). Port TCP 20000.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/jotonedev/openwebnet-dissector |
| Commit importé | `1822eeb618b89504068ecd1aaa61c7691cece43d` du 01/03/2023 (branche `main`, dernier commit ; dernière modification du script : `52e122d` du 28/01/2023) |
| Licence amont | MIT (`LICENSE` amont, © 2023 John Toniutti) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur OpenWebNet natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `openwebnet_dissector.lua` | Protocole `own` sur TCP 20000 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. La capture d'écran amont n'est pas importée.

## Utilisation

Copier `openwebnet_dissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `own`. Champs filtrables : `own.cmd`, `own.who`, `own.what`,
`own.where`…

## Remarques

- Documentation du protocole : [Legrand — Open Web Net for MyHOME](https://developer.legrand.com/documentation/open-web-net-for-myhome/)
  et [billet de l'auteur](https://jotone.eu/post/230128).
- Le champ `own.password` affiche le mot de passe OPEN échangé en clair :
  attention avant de partager une capture.
- Deux champs déclarent la même abréviation `own.value` (« Values » et
  « Value ») ; nonce et mot de passe sont déclarés en `uint16`, ce qui
  peut tronquer des valeurs longues. Laissé tel quel.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
