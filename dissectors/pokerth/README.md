# PokerTH — jeu de poker Texas Hold'em en réseau

Dissecteur Wireshark Lua du **protocole réseau de PokerTH**, jeu libre de
poker Texas Hold'em multijoueur : préfixe de longueur sur 4 octets avec
réassemblage TCP, puis décodage minimal des messages protobuf du
protocole (`pokerth.proto`) — annonce, initialisation, authentification
(défi / réponse / vérification), avatars, listes de joueurs et de
parties, informations joueur, création et entrée en partie, déroulement
du jeu (cartes, mises, pots, fin de main), discussion, erreurs… — avec
les noms des types de messages. Port TCP 7234.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/pokerth/pokerth (fichier `pokerth.lua` à la racine) |
| Commit importé | `ba57b8dcdc3d89010cfda3a1c1359038c4dd2424` du 31/10/2026 (branche `stable`, branche par défaut, dernier commit ; dernière modification de `pokerth.lua` : `4dc3fa3` du 18/04/2025) |
| Licence amont | AGPL-3.0-or-later (fichier `COPYING` AGPL v3, copié ici sous le nom `LICENSE` ; README : « GNU Affero General Public License version 3 or later », avec une permission supplémentaire pour OpenSSL sans objet ici ; le script n'a pas d'en-tête propre) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur PokerTH natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme du `COPYING` amont). La GPLv3 du dépôt permet la combinaison
avec du code AGPLv3 (article 13) ; précédents : `dissectors/aerospike/`,
`dissectors/space-coap/`.

## Fichiers

| Fichier | Rôle |
|---|---|
| `pokerth.lua` | Protocole `pokerth` sur TCP 7234 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le jeu lui-même (C++, Qt) n'est pas
importé.

## Utilisation

Copier `pokerth.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `pokerth`.

## Remarques

- Le serveur officiel chiffre les connexions (TLS) : seul le trafic en
  clair (serveur local, LAN) est lisible sans clés.
- Décodeur protobuf écrit à la main : seuls les messages et champs
  prévus par le script sont détaillés. Utilise `bit.band` /
  `bit.lshift` / `bit.rshift` (bibliothèque `bit` fournie par
  Wireshark 4.4 et plus) ; fonctions globales comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
