# Z-Wave Zniffer (trames radio Z-Wave et classes de commandes)

Dissecteurs Wireshark Lua du **protocole série Zniffer** de Silicon Labs
(firmware Zniffer 2.55 sur clé USB ZMEUZB1) et des **classes de commandes
Z-Wave**, pour analyser un réseau domotique Z-Wave au niveau radio : trames
Zniffer (fréquence/canal, vitesse, RSSI, horodatage), puis MPDU Z-Wave
(Home ID, nœuds source et destination, contrôle de trame, séquence,
longueur), et enfin la charge applicative (classe de commande, commande,
paramètres) avec nom de classe dans la colonne Info.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/alexkuehn/zwave-sniffer-suite (dossier `dissectors/`) |
| Commit importé | `8b9d61b667fd87cd00af61db694d94e5e0c840c4` du 13/07/2020 (branche `master`, dernier commit ; dernière modification des deux dissecteurs importés : `26e6231` du 12/07/2020) |
| Licence amont | LGPL-3.0-or-later — en-tête de chaque fichier importé : « Copyright C) 2020 Alexander Kühn », « GNU Lesser General Public License … either version 3 of the License, or (at your option) any later version » ; pas de fichier LICENSE dans le dépôt |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Z-Wave natif |

L'amont ne fournit pas le texte de la licence : textes de référence
https://www.gnu.org/licenses/lgpl-3.0.html et
https://www.gnu.org/licenses/gpl-3.0.html (la LGPL v3 complète la GPL v3).

## Fichiers

| Fichier | Rôle |
|---|---|
| `zniffer-dissector.lua` | Dissecteur `Zniffer` (encapsulation `wtap.USER0`) ; trames Zniffer et MPDU Z-Wave, puis appel du dissecteur USER2 |
| `zwave-command.lua` | Dissecteur `ZWaveCommand` (encapsulation `wtap.USER2`) ; classes de commandes Z-Wave |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête de chaque fichier (les en-têtes de licence
amont sont conservées).

**Non importé : `dissectors/zwserial.lua`** (API série Z-Wave entre
contrôleur et hôte, `wtap.USER1`) — ni en-tête de licence, ni fichier
LICENSE dans le dépôt : sans licence, il reste sous droit d'auteur exclusif.
Non importés non plus : les extcap Python (`extcap/`), l'outil
`contrib/zw-sapi-tap.py` et la documentation (sans licence).

## Utilisation

Copier les deux fichiers `.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua. Les
trames sont attendues en encapsulation DLT USER0 : capture via l'extcap
Zniffer amont (non importé), ou fichier pcap avec ce type de lien. Filtrer
avec `zniffer` ou `zwavecommand`.

## Remarques

- Le dissecteur Zniffer affecte `pinfo.cols.rssi`, qui n'est pas un nom de
  colonne standard de l'API Lua de Wireshark ; selon la version, cette ligne
  peut lever une erreur Lua en fin de dissection (non vérifié).
- L'encapsulation 47 appelée en dur correspond à `wtap.USER2`.
- Décodage incomplet et sans déchiffrement des trames Z-Wave S0/S2
  (README amont) ; preuve de concept de 2020.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
