# Orvibo S20 / WiWo — prises Wi-Fi connectées

Dissecteur Wireshark Lua du **protocole UDP des prises Wi-Fi Orvibo S20**
(gamme WiWo) : en-tête « magic », longueur et commande, puis découverte
(`qa`, `qg`), abonnement (`cl`), contrôle et état de la prise (`dc`,
`sf`), lecture et écriture des tables internes (`rt`, `tm` — table des
appareils, des minuteries…), battement (`hb`), réglage de l'heure… avec
préférences de port, de niveau de débogage et d'heuristique. Port UDP
10000 par défaut.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/starox/wireshark.orvibo |
| Commit importé | `bb5afa9b700feb6ff729f0c6885b373f36709f44` du 06/02/2016 (branche `master`, dernier commit, qui est aussi la dernière modification de `wiwo_orvibo.lua`) |
| Licence amont | GPL-2.0-or-later (fichier `COPYING` GPL v2, copié ici sous le nom `LICENSE` ; en-tête : « either version 2 of the License, or (at your option) any later version », © 2016 Frédéric Leroy) ; captures dans le domaine public (README amont) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Orvibo natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme du `COPYING` amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `wiwo_orvibo.lua` | Protocole `orvibo` sur UDP 10000 (port réglable dans les préférences) |
| `captures/orvibo_s20_capture_1.pcapng` | Capture amont (44 Ko) |
| `captures/orvibo_s20_capture_3_control_by_gateway_outside_of_local_lan.pcapng` | Capture amont : pilotage via la passerelle Orvibo hors du réseau local (186 Ko) |
| `captures/orvibo_s20_capture_4.pcapng.pcap` | Capture amont (302 Ko) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête du script. **Non importée** : la
capture `orvibo_s20_capture_2_no_internet_access_on_wifi_network.pcapng`,
qui contient l'appairage Wi-Fi « smart_config » de la prise (par
précaution, ces trames pouvant transporter les identifiants du réseau
Wi-Fi de l'auteur).

## Utilisation

Copier `wiwo_orvibo.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer
`wireshark -X lua_script:wiwo_orvibo.lua captures/orvibo_s20_capture_1.pcapng`,
puis filtrer avec `orvibo`.

## Remarques

- Selon le README amont, plusieurs champs sont inconnus, incomplets ou
  inexacts (`cd`, `cs`, `gt`…) et la table de minuteries n° 3 n'est pas
  décodée.
- Les captures contiennent les mots de passe d'accès distant des prises
  de test de l'auteur (dont la valeur par défaut `888888`), tels que
  publiés en amont.
- Non vérifié dans Wireshark.
