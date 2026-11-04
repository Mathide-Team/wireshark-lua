# SeismoCloud (capteurs sismiques, interface de commande locale)

Dissecteur Wireshark Lua de l'**interface de commande locale SeismoCloud**
(application ↔ capteur), utilisée par les sismomètres du réseau
participatif SeismoCloud (université La Sapienza de Rome) sur UDP 62001 :
octets magiques, puis commande — DISCOVERY / DISCOVERY_REPLY, PING / PONG,
STREAM_START / STREAM_STOP, SENDGPS, OK, SETSYSLOG, REBOOT, GETINFO /
GETINFO_REPLY — avec décodage de l'adresse MAC, des coordonnées GPS et
des informations du capteur.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/sapienzaapps/galileo-terremoti (fichier `seismocloud.lua`) |
| Commit importé | `82e894e7ab4a7f289a50aaed1cf88c11c44b459d` du 23/01/2019 (branche `master`, dernier commit ; dernière modification du dissecteur : `990acba` du 30/10/2017) |
| Licence amont | GPL-3.0-only (`LICENSE` amont : texte de la GPL v3, sans mention « or any later version » ; README amont : « See LICENSE file » ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur SeismoCloud natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `seismocloud.lua` | Dissecteur `seismoproto` (UDP 62001) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `seismocloud.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) — plutôt que la méthode amont
historique `dofile` dans `init.lua` — recharger les plugins Lua, puis
filtrer avec `seismoproto`.

## Remarques

- Le projet amont (Raspberry Pi ; Intel Galileo abandonné) n'est plus
  maintenu depuis 2019 ; le protocole a pu évoluer dans les capteurs
  récents (non vérifié).
- Variables et fonctions globales (`seismoproto`, `mac2string`,
  `udp_table`…) comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
