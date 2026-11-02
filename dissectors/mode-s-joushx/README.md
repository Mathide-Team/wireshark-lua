# Mode S / ADS-B — flux brut dump1090 (joushx)

Dissecteurs Wireshark Lua des réponses Mode S des transpondeurs
d'avions, reçues sous forme d'octets bruts sur TCP 30002. Ce flux vient
de dump1090 modifié par le correctif amont. `modes` décode le format
de liaison descendante (DF), l'adresse OACI, la parité, ainsi que
l'altitude ou l'identité (squawk) des messages courts.
`adsb` décode les squitters étendus DF 17 : indicatif, position
(altitude, CPR), vitesse, état. `commb` n'affiche qu'un en-tête
pour les DF 20, 21 et 24 (issue #527).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/joushx/mode-s-dissector (`modes.lua`, `adsb.lua`, `commb.lua`, `example.pcapng`) |
| Commit importé | `6543ebf2b97f50d0ade998a99f630afae56ad873` du 25/05/2016 (dernier commit de `master`) ; dernière modification des trois scripts : commit `f32ea2d8480da7da5ddbc397cfc8ee42d25da1f1` du 24/05/2016 ; capture : commit `34d1c9a57fef1fe43c8e5cf419afaeecb9561471` du 24/05/2016 |
| Licence amont | GPL-2.0 : `LICENSE` du dépôt (texte GNU GPL v2), sans mention « ou ultérieure » de l'auteur ni en-tête dans les scripts, d'où `GPL-2.0-only`. Licence propre au dossier, comme `dissectors/avionique` |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur Mode S ni ADS-B dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Les scripts sont repris tels quels (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête de chacun (convention du dépôt, issue #563). Le
correctif dump1090 et la capture d'écran amont ne sont pas importés.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/modes.lua` | Protocole `modes` (« Mode S ») sur TCP 30002 (ligne 89) ; appelle `adsb` (DF 17) ou `commb` (DF 20, 21, 24) |
| `src/adsb.lua` | Protocole `adsb` (« ADS-B ») : code de type, indicatif, position, vitesse, état |
| `src/commb.lua` | Protocole `commb` (« Comm-B ») : en-tête seul, aucun champ |
| `captures/example.pcapng` | Capture amont (57 460 octets, 476 trames, toutes des segments de données sur la boucle locale, TCP 30002) |

## Utilisation

Copier les trois fichiers de `src/` dans le dossier des plugins Lua
personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »),
puis Ctrl+Maj+L. `modes.lua` trouve `adsb` et `commb` lors du décodage,
quel que soit l'ordre de chargement. La source doit être un dump1090
(MalcolmRobb) corrigé par le patch amont
`0001-Make-dump1090-output-raw-bytes-instead-hex-modstring.patch`. Sa
sortie 30002 est lue avec un client TCP (`nc localhost 30002`) et la
boucle locale est capturée. Filtres : `modes`, `adsb`, `adsb.ident`,
`modes.df == 17`.

## Vérification à l'import

tshark 4.6.4, trois scripts chargés par `-X lua_script:` : aucun message
d'erreur au chargement (`luac5.4 -p` : OK).

Sur `captures/example.pcapng`, les 476 segments TCP 30002 sont tous
décodés, sans aucune erreur Lua :

| Info | Trames |
|---|---|
| Mode S Elementary Surveillance | 266 |
| Comm-B | 57 |
| Mode S Altitude | 56 |
| ADS-B Velocity | 29 |
| Mode S Identity | 25 |
| ADS-B Position | 24 |
| ADS-B Identification | 11 |
| Mode S Enhanced Surveillance | 5 |
| ADS-B (autre code de type) | 3 |

Exemples : indicatifs `DKNOP__`, `DLH2JV_`, `OEALB__` ; position
« Airborne position (Baro Alt) » à `34525 ft = 10523.22 m`.

## Limites constatées

- Longueur des segments : 17 octets (message court) ou 31 (long) dans
  la capture. Le correctif ne réduit pas le compteur
  (`(msgLen*2) + 3`) : chaque segment porte des octets résiduels après
  le message. Le dissecteur s'y fie (`buffer:len() == 31`, ligne 32 de
  `modes.lua`) : un flux sans ces octets ou plusieurs messages par
  segment ne sont pas décodés correctement.
- Champ `CA` (capacité) affiché sous le nom « Subtype » avec des
  libellés de sous-types ADS-B (ligne 12 de `modes.lua`), par exemple
  « Surface position (6) » pour un avion en vol.
- Indicatif restitué sur 7 caractères pour 8 lettres décodées.
- Drapeau « Time » inversé (`0` affiché « UTC », ligne 40 de `adsb.lua`).
- Pas de vérification de parité (CRC Mode S) ni de décodage CPR en
  latitude et longitude ; Comm-B non décodé ; la plupart des messages
  courts (DF 0, 11, 16) restent « Elementary Surveillance » ; le README
  amont prévient lui-même que le script est « very alpha ».
- Variables globales (`decode_parity`, `tcp_table`, protos).
