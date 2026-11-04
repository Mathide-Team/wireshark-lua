# SQD — Simple Quantar Dissector (V.24 Quantar / P25)

Dissecteurs Wireshark Lua du protocole **V.24 des stations de base
Motorola Quantar** (aussi appelé Digital Conventional Infrastructure
Interface), tel qu'il circule sur IP dans les réseaux P25 radioamateurs,
par John Yaldwyn (ZL4JY). Deux variantes presque identiques :

- `Qv24_P25NX.lua` (version 2, novembre 2016) : protocole `QV24_P25NX`
  pour les trames V.24 encapsulées dans le tunnel série Cisco **STUN**
  (« P25NX V2 ») — longueur et identifiant STUN, champs HDLC (adresse,
  contrôle, type de trame, poll/final), puis champs P25 : type de trame,
  RT/RT, site, RSSI, Link Control (opcode, MFID), options de service
  (urgence, protégé, duplex, mode, priorité), adresses cible / source,
  données basse vitesse, IV de chiffrement, ALGID et KEYID ; ports UDP
  30000 et TCP 1994 ;
- `Qv24_UDP.lua` (version 1.5, septembre 2016) : protocole `QV24_UDP`
  pour les trames V.24 « nues » sur UDP (sans enveloppe STUN), décodage
  plus sommaire ; port UDP 30000.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ZL4JY/SQD |
| Commit importé | `4192d56e6a1f11531cf7be6659f2f80fb5aaf299` du 17/11/2016 (branche `master`, dernier commit ; dernières modifications : `Qv24_P25NX.lua` `b24ca10` du 17/11/2016, `Qv24_UDP.lua` `978fbcb` du 18/09/2016) |
| Licence amont | GPL-3.0 : en-tête des scripts « either version 3 of the License, see: http://www.gnu.org/licenses/ » (sans « or later »), Copyright 2016 John Yaldwyn ZL4JY ; fichier `LICENSE` amont GPLv3, copié ici ; d'où `GPL-3.0-only` |
| Natif Wireshark 4.6.4 | Non — ni Quantar V.24 ni STUN Cisco (`stun` natif est le STUN des NAT, sans rapport) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `Qv24_P25NX.lua` | Protocole `QV24_P25NX`, UDP 30000 et TCP 1994 |
| `Qv24_UDP.lua` | Protocole `QV24_UDP`, UDP 30000 |
| `LICENSE` | Licence GPLv3 amont |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. `FAQ.md` et `Versions` amont ne sont pas
repris.

## Utilisation

Le README amont décrit un chargement par `dofile()` depuis `init.lua`
(Windows) ; il suffit aujourd'hui de copier le script voulu dans le
dossier `plugins` de Wireshark, puis de filtrer avec `qv24_p25nx` ou
`qv24_udp`.

## Remarques

- **Conflit interne** : les deux scripts s'enregistrent sur le port UDP
  30000 ; installés ensemble, le dernier chargé l'emporte. N'installer que
  la variante correspondant au transport utilisé (ou utiliser « Décoder
  comme… »).
- Les deux scripts utilisent la même variable globale `p_QV24` (et une
  variable globale `dissector`) ; `Qv24_P25NX.lua` déclare des champs aux
  préfixes `cisco_stun.` et `hdlc.` hors de son propre protocole.
- D'après le README amont, la version 1.5 de `Qv24_UDP.lua` n'intègre pas
  encore les mises à jour de DG9BEW reprises dans `Qv24_P25NX.lua`.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
