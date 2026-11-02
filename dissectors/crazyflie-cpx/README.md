# Crazyflie CPX — protocole de l'AI-deck (NanoCockpit)

Dissecteurs Wireshark Lua du protocole CPX (Crazyflie Packet eXchange).
Ce protocole relie les processeurs du nano-drone Crazyflie et de son
AI-deck (STM32, ESP32, GAP8) à l'ordinateur hôte par Wi-Fi. Ils viennent
du cadriciel NanoCockpit de l'IDSIA. `cpx` décode le transport TCP :
longueur, en-tête de routage avec destination, source, dernier paquet,
fonction et version. `cpx_udp` décode le transport UDP (numéro de
séquence et même en-tête). `cpx_streamer` décode la fonction
`STREAMER` (`0x06`) : début et données d'un tampon d'image,
d'inférence ou de « fog buffer » (issue #529).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/idsia-robotics/nanocockpit (`tools/wireshark/cpx_tcp.lua`, `cpx_udp.lua`, `cpx_streamer.lua`) |
| Commit importé | `741f12b2c4fc7162c019b7932bb8d5b4ddde677b` du 05/05/2026 (dernier commit de `main`) ; dernière modification des trois scripts : commit `1d1487441d68baacfde7ebd099480716047fe2ea` du 05/03/2025 |
| Licence amont | Apache-2.0 : `LICENSE` du dépôt (les scripts portent « Copyright (c) 2023, Elia Cereda, All rights reserved » sans autre mention). `cpx_tcp.lua` et `cpx_udp.lua` reprennent la structure des exemples `dissectFPM.lua` et `dissector.lua` de Wireshark (Hadriel Kaplan, domaine public ou BSD-3-Clause). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur CPX dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Les scripts sont repris tels quels (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête de chacun (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/cpx_tcp.lua` | Protocole `cpx` (« CPX ») sur TCP 5000 (lignes 167 et 507), réassemblage et plusieurs messages par segment ; table `cpx.function` (ligne 289) |
| `src/cpx_udp.lua` | Protocole `cpx_udp` (« CPX UDP ») sur UDP 5000 (lignes 60 et 346), préférence `cpx_udp.port` ; table `cpx_udp.function` (ligne 249) |
| `src/cpx_streamer.lua` | Protocole `cpx_streamer` (ligne 61), inscrit sous la fonction `0x06` des deux tables (lignes 115 et 116) |

## Utilisation

Copier les trois fichiers de `src/` dans le dossier des plugins Lua
personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »).
Recharger ensuite avec Ctrl+Maj+L. L'ordre de chargement est sans
importance (l'inscription de `cpx_streamer` se fait à l'initialisation).
Filtres : `cpx`, `cpx_udp`, `cpx_streamer`, `cpx.function == 6`. Autre
port UDP : `-o cpx_udp.port:5001`.

## Vérification à l'import

`luac5.4 -p` : OK pour les trois scripts. tshark 4.6.4, chargés par
`-X lua_script:`, puis copiés dans le dossier des plugins : aucun
message au chargement. Captures synthétiques construites d'après le
client Python amont (`src/client/aideck_cpx_streamer/.../cpx/cpx.py`,
`transport/tcp.py`, `transport/udp.py`) :

| Essai | Résultat |
|---|---|
| TCP 5000 : CRTP hôte → STM32 | « CPX: WIFI_HOST → STM32, Len=7, Func=0x03, Unknown » |
| TCP : deux messages dans un segment (`BUFFER_BEGIN` image de 4000 octets, `BUFFER_DATA`) | les deux décodés : en-tête de routage, `Command`, `Type: IMAGE`, `Size: 4000 bytes`, `Checksum: 0xdeadbeef`, données |
| TCP : message console réparti sur deux segments | réassemblé : « CPX: ESP32 → WIFI_HOST, Len=20, Func=0x02 » |
| UDP 5000 : les mêmes messages, numérotés | décodés de même (« CPX UDP ») |
| UDP de 3 octets | **erreur Lua** `cpx_udp.lua:276` (`attempt to index a nil value (global 'tree')`) |
| `BUFFER_BEGIN` tronqué (3 octets) | **erreur Lua** `cpx_streamer.lua:160` (`Range is out of bounds`) |

## Limites constatées

- Le champ `Length` affiche la longueur totale du message (en-tête de 4
  octets compris) à côté de la valeur brute : « 22 bytes (0x0012) »
  (ligne 393 de `cpx_tcp.lua`).
- Paquet UDP trop court : le contrôle prévu échoue sur une variable
  `tree` non définie (ligne 276 de `cpx_udp.lua`) ; `cpx_streamer` ne
  contrôle pas la longueur.
- Seule la fonction `STREAMER` a un sous-dissecteur ; CRTP, console,
  Wi-Fi, application, etc. restent en données brutes (« Unknown »).
- Le dossier d'origine reste un tutoriel adapté : commentaires de
  l'exemple FPM/DNS de Wireshark conservés (`cpx_tcp.lua` parle encore
  de « Quagga FPM Netlink »).
- Pas de capture réelle disponible.
