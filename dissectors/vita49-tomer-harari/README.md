# VITA 49.2 — Tomer Harari

Dissecteur Wireshark Lua du **VITA 49.2** (VITA Radio Transport, VRT) et
du profil **DIFI** sur UDP. Il décode :
- les paquets de données, de contexte et de commande ;
- le prologue : type, Class ID, horodatages TSI/TSF, compteur, taille ;
- plusieurs paquets VRT dans un même datagramme ;
- le parcours complet du CIF0 : fréquences radix 20 converties en Hz,
  niveaux en dB, blocs GPS/INS ;
- les champs de version du CIF1 ;
- le préambule des commandes : mot CAM, Message ID, Controllee et
  Controller ;
- les indicateurs de la remorque des paquets de données ;
- le marquage DIFI par son OUI `0x6A621E`.

Il signale par info d'expert les trous de compteur, les tailles
incohérentes et les pertes d'échantillons (issue #511).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Tomer-Harari/vita49.2-wireshark-dissector (`vita49.lua`) |
| Commit importé | `1f5ab2ba2b5c072596c89e742c7cd524b262d638` du 04/08/2026 (dernier commit de la branche par défaut `main`, et dernière modification de `vita49.lua`) |
| Licence amont | MIT, « Copyright (c) 2026 Tomer Harari » (`LICENSE` du dépôt), compatible avec la licence de ce dépôt (GPL-3.0-or-later) |
| Natif Wireshark 4.6.4 | Oui, en partie : `vrt` (« VITA 49 », `packet-vrt.c`) sur UDP 4991 ; ce script prend sa place sur ce port (voir Limites) |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563). La capture
`tests/corpus.pcap` (40 paquets du paquetiseur RTL de
[vita49.2-core](https://github.com/Tomer-Harari/vita49.2-core)) est copiée
telle quelle dans `captures/`. Le générateur de captures et la suite de
tests amont (`tools/make_test_pcap.py`, `tests/run_tests.py`) ne sont pas
importés : ils supposent l'arborescence amont.

Autres dissecteurs du même domaine dans ce dépôt : `difi-consortium` et
`difi-jo-rivera` (profil DIFI seul).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/vita49.lua` | Protocole `vita49` (« VITA 49.2 Radio Transport ») sur UDP 4991 (ligne 432), plage de ports modifiable (préférence « UDP ports », ligne 148), heuristique UDP (ligne 451) ; aucune variable globale |
| `captures/corpus.pcap` | 40 paquets VRT réels émis par le paquetiseur RTL amont |

## Utilisation

Copier `src/vita49.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis Ctrl+Maj+L,
ou sans installation :

```sh
tshark -X lua_script:vita49.lua -r captures/corpus.pcap
```

Filtres : `vita49`, `vita49.type == 4`, `vita49.rf_freq_hz > 100e6`,
`vita49.sid`, `vita49.cam_action == 2`, `_ws.expert.message contains "gap"`.

## Vérification à l'import

tshark 4.6.4 (Lua 5.4) : le fichier se charge sans erreur
(`luac5.4 -p` : OK).

| Essai | Résultat |
|---|---|
| Suite amont lancée dans le dépôt amont (`make_test_pcap.py` puis `run_tests.py`, `TSHARK=tshark`) | `PASS: 28 packets field-exact, expert checks correct, corpus 40/40 clean` |
| `captures/corpus.pcap` | 40 trames `VITA-49.2` |
| Infos d'expert de la capture de test amont | trame 24 « Packet count gap », 25 « Packet Size exceeds the remaining datagram bytes », 27 « Trailer signals sample loss » |
| Même capture sans le script | 27 trames prises par le natif `VITA 49`, 1 laissée à UDP (port non standard) |
| Capture DIFI GNU Radio de `jo-rivera/difi-wireshark-dissector` (22 624 trames, UDP 50003) | toutes reconnues par l'heuristique ; contexte : CIF0 `0x00000000`, donc aucun champ de contexte détaillé (données restées dans `Payload`) |
| Synthétique : datagramme quelconque de 12 octets dont les octets 2 et 3 valent `0x0003` | **pris par l'heuristique** (« Packet Type: Unknown (13) ») puis erreur Lua `vita49.lua:353: Range is out of bounds` |

## Limites constatées

- **Heuristique très permissive** (lignes 436 à 451). Elle n'exige que des
  champs Packet Size cohérents avec la longueur du datagramme : tout
  datagramme UDP non réclamé dont les octets 2 et 3 donnent sa longueur en
  mots de 32 bits est pris pour du VRT, ce qui peut finir par une erreur
  Lua. Désactiver l'heuristique (`vita49_udp`, « Analyser › Protocoles
  activés ») si elle gêne.
- Remplace le dissecteur natif `vrt` sur UDP 4991 tant que le script est
  chargé (filtres `vrt.*` sans effet sur ce port).
- CIF1 : seuls les champs de version sont décodés. Tout autre champ CIF1
  arrête le décodage détaillé avec une note d'expert (ligne 247).
- DIFI reconnu par l'OUI `0x6A621E` seulement ; la capture GNU Radio de
  jo-rivera, qui utilise `0x7C386C`, n'est donc pas marquée DIFI.
