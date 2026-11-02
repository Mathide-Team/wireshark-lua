# VXSDR — protocole de commande et de données de libvxsdr

Dissecteur Wireshark Lua fourni avec libvxsdr, la bibliothèque hôte des
radios logicielles VXSDR de Vesperix. Il décode l'en-tête de 8 octets
des paquets UDP (type de paquet sur 6 bits, commande sur 6 bits,
drapeaux sur 4 bits, sous-appareil, voie, taille, compteur de
séquence), puis les arguments des commandes d'appareil et de radio
(heure, fréquence, gain, débit, correction IQ, démarrage, boucle…), de
leurs réponses et de leurs erreurs, et les messages asynchrones. Ports
UDP 1030 (commandes) et 1031 (données) (issue #948).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/vesperix/libvxsdr (`tools/vxsdr_dissector.lua`) |
| Commit importé | `ab9976199d0a3a6664150533380095399708f819` du 19/05/2026 (dernier commit de la branche par défaut `main`) ; dernière modification du fichier : commit `92bc327fd4bc37f135276df3baeae57fb50f4b11` du 28/08/2024 |
| Licence amont | GPL-3.0-or-later : `LICENSE.md` du dépôt (« GNU General Public License, either version 3.0 or (at your option) any later version », avec mention de licences commerciales alternatives proposées par Vesperix) et en-tête SPDX du script (© 2023 Vesperix Corporation) |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur VXSDR dans `tshark -G protocols` |

Texte de la licence : fichier `LICENSE.md` de ce dossier (copie
conforme du `LICENSE.md` amont). Le fichier est repris tel quel (aucune
modification) ; seule l'en-tête de provenance de cinq lignes est ajoutée
en tête de `vxsdr_dissector.lua` (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/vxsdr_dissector.lua` | Protocole `vxsdr` (« VXSDR Protocol », ligne 9) ; ports (ligne 11) ; types de paquets (ligne 15), commandes d'appareil (ligne 43) et de radio (ligne 128) ; masques et champs `vxsdr.*` (lignes 193 à 282) ; dissecteur ligne 285 ; inscription sur UDP 1030 et 1031 lignes 500 et 501 |

## Utilisation

Copier `src/vxsdr_dissector.lua` dans le dossier des plugins Lua
personnels (`~/.local/lib/wireshark/plugins/`), ou le charger par
`-X lua_script:`. Le trafic des ports UDP 1030 et 1031 est attribué à
VXSDR. Mais voir les limites : avec Wireshark 4.6.4, chaque paquet
provoque une erreur Lua.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, par `-X lua_script:` et dans le
dossier des plugins : chargement sans erreur, protocole `vxsdr` présent
dans `tshark -G protocols`. Le dépôt amont ne contient aucune capture.
Essais sur une capture synthétique (UDP 1030), non commitée ; en-tête
comparé à `include/vxsdr_packets.hpp` et `include/packet_header.h` du
même commit :

| Essai | Résultat |
|---|---|
| Les dix paquets, fichier importé | Erreur Lua « attempt to index a nil value (global 'bit32') » (ligne 289) sur chaque paquet ; seule la colonne Protocole indique « VXSDR » |
| Copie d'essai non commitée, précédée de `local bit32 = bit` : DEVICE_CMD HELLO et sa réponse (8 entiers) | « Packet Type: DEVICE_CMD (0x02) », « Device Command: HELLO (0x00) » ; huit « UInt32 Data » |
| Même copie : RX_RADIO_CMD SET_RF_FREQ 1,42 GHz, réponse GET_RF_FREQ, erreur BAD_PARAMETER | « Frequency (Hz): 1.42e+09 », « Relative Tolerance: 1e-06 » ; « Radio Error Reason: BAD_PARAMETER (0x00000008) » |
| Même copie : TX_RADIO_CMD SET_SAMPLE_RATE avec drapeau 0x1 | « Rate (Hz): 2e+06 », « Flags: 0x1 » |
| Même copie : réponse GET_TIMING_STATUS (valeur 5) | PPS externe True, 10 MHz externe False, oscillateur de référence True |
| Même copie : ASYNC_MSG DATA_UNDERFLOW du système RX | « Async Message Type: DATA_UNDERFLOW (0x1) », mais « Async Message System: Unknown (0x1) » |
| Même copie : paquet de 3 octets | Erreur Lua « Range is out of bounds » (ligne 291) |
| Même copie : SET_TIME_NOW annonçant 16 octets, 10 reçus | Erreur Lua « Range is out of bounds » (ligne 332) |

## Limites constatées

- Le script appelle la bibliothèque `bit32` de Lua 5.2 (lignes 289 et
  290), absente de Wireshark 4.6.4 (Lua 5.4) : chaque paquet provoque
  une erreur et rien n'est décodé. La bibliothèque `bit` de Wireshark
  fournit les mêmes fonctions.
- Le système d'un message asynchrone est extrait par le masque 0x0C00
  (ligne 198), soit une valeur de 0 à 3, mais la table `async_sys_id`
  (ligne 121) attend 0x10, 0x20 ou 0x30 : tout système autre que 0
  s'affiche « Unknown ». L'auteur l'indique (« FIXME: these need
  testing », ligne 196).
- Les drapeaux ne sont affichés qu'en bloc (« Flags ») ; les champs par
  drapeau sont commentés (« FIXME: still doesn't display flags
  properly », ligne 219). Plusieurs champs sont nommés `vxsddr.*` (faute
  de frappe, lignes 220 à 255).
- La taille du paquet est lue avant le contrôle de longueur minimale
  (ligne 291), et les arguments ne sont pas contrôlés : un paquet court
  provoque une erreur Lua. `tvbuf(0, pktlen)` (ligne 293) utilise une
  variable inexistante (`pkt_len` est la bonne).
- Les échantillons des paquets de données (port 1031) ne sont pas
  décodés ; la colonne Info n'est pas renseignée.
