# VOTER — protocole des récepteurs votants d'AllStarLink

Dissecteur Wireshark Lua du protocole VOTER (« Voice Observing Time
Extension for Radio », créé par Jim Dixon, WB6NIL) : les cartes
VOTER/RTCM envoient au serveur Asterisk (`chan_voter`) l'audio de leurs
récepteurs radio, horodaté par GPS et accompagné du niveau de signal,
pour que le serveur retienne le meilleur récepteur. Le script décode
l'en-tête (secondes, nanosecondes ou numéro de séquence, défi et
réponse d'authentification, type de charge utile) et les charges
utiles authentification + options, RSSI + audio µ-law, GPS,
RSSI + audio ADPCM et ping, sur UDP 667 (issue #944). Auteur : Mason
Nelson, N5LSN.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/AllStarLink/Voter (`VOTER-dissector/voter.lua`) |
| Commit importé | `d85a1d796e7aaec4a5df0c349a6f04e528b5c1d1` du 24/10/2026 (dernier commit de la branche par défaut `master`) ; dernière modification du fichier : commit `8f4e65ad78ed3e0be175bac32603f5a92ddc75f6` du 31/05/2024 |
| Licence amont | AGPL-3.0-only : `LICENSE` du dépôt (texte de l'AGPLv3, sans mention « or later ») ; le script n'a pas d'en-tête de licence. Comme pour `aerospike`, la licence est conservée telle quelle (la GPLv3 permet de combiner avec l'AGPLv3, article 13), sans re-licenciement |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur VOTER dans `tshark -G protocols` |

Texte de la licence : fichier `LICENSE` de ce dossier (copie conforme
du `LICENSE` amont). Le fichier est repris tel quel (aucune
modification ; pas de fin de ligne finale, comme l'amont) ; seule
l'en-tête de provenance de cinq lignes est ajoutée en tête de
`voter.lua` (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/voter.lua` | Protocole `voter` (« VOTER Protocol », ligne 15, variable globale) ; champs `voter.*` (lignes 18 à 31) ; dissecteur ligne 34 ; inscription sur UDP 667 ligne 104 |

## Utilisation

Copier `src/voter.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`), ou le charger par
`-X lua_script:voter.lua`. Le trafic du port UDP 667 (port par défaut
des cartes VOTER) est décodé. Filtres : `voter`, `voter.payload_type`,
`voter.rssi`, `voter.flags`, `voter.longitude`, `voter.latitude`…

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, par `-X lua_script:` et dans le
dossier des plugins : chargement sans erreur. Le dépôt amont ne
contient aucune capture. Essais sur une capture synthétique (UDP 667),
non commitée ; formats comparés au micrologiciel du même dépôt
(`VOTER_RTCM-firmware/build-files/ASL-VOTER.X/src/Voter.c`, structures
`VOTER_PACKET_HEADER`, `audio_packet`, `gps_packet`) :

| Essai | Résultat |
|---|---|
| Authentification avec octet d'options (25 octets) | « [0 - Auth + Flags] Seconds: 1793612187, Nanoseconds: 500000000 », Flags 0x22 |
| Authentification sans options (en-tête seul, 24 octets) | Erreur Lua « Range is out of bounds » (ligne 74) |
| µ-law : RSSI 200 + 160 octets | « [1 - RSSI + Mu-law] », RSSI 200 |
| GPS : `4848.120N`, `00747.540E`, `150.0M` | Champs inversés : « Longitude: 4848.120N », « Latitude: 00747.540E » |
| ADPCM : RSSI 128 + 163 octets | « [3 - RSSI + ADPCM] », RSSI 128 |
| Ping avec 8 octets | « [5 - PING] », données affichées |
| Types 4 et 9 | « [4 - RESERVED] » et « Unknown Payload Type: 9 », erreur « Unknown payload type » dans les deux cas |
| Paquet de 10 octets | Erreur Lua « Range is out of bounds » (ligne 40) |
| µ-law tronqué (100 octets d'audio) | Erreur Lua « Range is out of bounds » (ligne 78) |

## Limites constatées

- Les libellés GPS sont inversés : le micrologiciel envoie
  `lat[9]` puis `lon[10]` puis `elev[7]`, mais le script appelle
  « Longitude » les 9 premiers octets et « Latitude » les 10 suivants
  (lignes 83 et 84). Les valeurs sont justes, les noms des champs
  `voter.longitude` et `voter.latitude` sont échangés.
- Aucune vérification de longueur : un paquet plus court que l'en-tête,
  une authentification sans octet d'options (envoyée par le
  micrologiciel tant qu'il n'est pas authentifié) ou un audio tronqué
  provoquent une erreur Lua au lieu d'un avertissement.
- L'audio µ-law et ADPCM est affiché en octets bruts, sans décodage ni
  lecture RTP.
- Le défi d'authentification est affiché comme une chaîne ; la réponse
  (`digest`) n'est pas vérifiée.
- Le type 4 est reconnu dans la colonne Info (« RESERVED ») mais signalé
  comme inconnu dans l'arbre.
- `voter_proto` est une variable globale (ligne 15).
- Seul le port UDP 667 est inscrit.
