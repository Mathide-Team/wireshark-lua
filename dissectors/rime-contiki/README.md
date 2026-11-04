# Rime — pile de communication de Contiki (réseaux de capteurs 802.15.4)

Dissecteurs Wireshark Lua de **Rime**, pile de communication légère du
système Contiki pour réseaux de capteurs sans fil IEEE 802.15.4 : en-tête
MAC 802.15.4 (champ de contrôle, séquence, PAN, adresses, CRC), en-tête
ContikiMAC éventuel (octet nul, longueur) et en-tête Rime (canal, type et
identifiant de paquet, adresses Rime source et destination), puis charge
utile. Un script par combinaison couche RDC × primitive Rime : RDC
**ContikiMAC** (`cmac`) ou **NullRDC** (`nullrdc`), primitives **abc**
(diffusion anonyme), **ibc** (diffusion identifiée), **uc** (unicast) et
**ruc** (unicast fiable). Chaque script remplace le dissecteur de
l'encapsulation `IEEE802_15_4`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/g-gaston/rime-dissector (dossier `lua-files/`) |
| Commit importé | `5c12ff74dca163a6b7db15aec29988f7f82d25a2` du 14/06/2014 (branche `master`, dernier commit ; dernière modification des scripts : `7757086` du 14/06/2014) |
| Licence amont | MIT (`LICENSE` amont, © 2014 Guillermo Gastón) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Rime natif (802.15.4 natif `wpan`) |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `rime-cmac-abc.lua` | ContikiMAC + diffusion anonyme |
| `rime-cmac-ibc.lua` | ContikiMAC + diffusion identifiée |
| `rime-cmac-uc.lua` | ContikiMAC + unicast |
| `rime-cmac-ruc.lua` | ContikiMAC + unicast fiable |
| `rime-nullrdc-abc.lua` | NullRDC + diffusion anonyme |
| `rime-nullrdc-ibc.lua` | NullRDC + diffusion identifiée |
| `rime-nullrdc-ruc.lua` | NullRDC + unicast fiable |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête. **Non importés** :
`rime-nullrdc-uc.lua`, qui contient une erreur de syntaxe amont
(parenthèse en trop ligne 100 : `…buffer(14,1):uint())`) et ne se charge
pas, et le script `wireshark-rime.bash` (copie avec `sudo` dans
`/usr/share/wireshark` et modification du `init.lua` système).

## Utilisation

Choisir **un seul** script selon la couche RDC et la primitive Rime de la
capture, puis lancer par exemple
`wireshark -X lua_script:rime-cmac-ruc.lua capture.pcap` (équivalent sans
`sudo` du script amont), et filtrer avec `rime`.

## Remarques

- **Effets de bord à connaître** : chaque script écrase la variable
  globale `table` (bibliothèque standard Lua) par
  `table = DissectorTable.get("wtap_encap")`, ce qui peut casser les
  autres plugins Lua chargés qui utilisent `table.insert`, `table.concat`…
  Il remplace aussi le dissecteur 802.15.4 natif (`wpan`) pour toute
  l'encapsulation `IEEE802_15_4`. À charger seul, ponctuellement, via
  `-X lua_script:`.
- Les huit scripts déclarent le même protocole `rime` : jamais deux à la
  fois.
- Décodage figé (adresses courtes, sans sécurité 802.15.4) ; libellés
  partiellement en espagnol (« Comando »).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
