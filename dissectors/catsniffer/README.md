# CatSniffer (Electronic Cats)

Dissecteurs Wireshark Lua des **trames capturées par le renifleur radio
multiprotocole CatSniffer** d'Electronic Cats (BLE, IEEE 802.15.4 /
Zigbee / Thread, LoRa) :

- outils historiques `pycatsniffer_bv3` (`legacy/`) : en-tête « CatSniffer
  Radio Packet Info » (version, interface, protocole, PHY, fréquence,
  canal, RSSI, statut), méta-en-tête BLE transmis ensuite au dissecteur
  natif `btle`, et variante LoRa (bande passante, facteur d'étalement,
  taux de codage, charge utile) ;
- outil actuel `catnip` (`catnip/`) : post-dissecteur qui réaffiche en
  texte ASCII la charge utile LoRa décodée par le dissecteur natif LoRaTap.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ElectronicCats/CatSniffer-Tools |
| Commit importé | `8a34319dd50c560f15aeada3bfdacc2a3f838dab` du 22/10/2026 (branche `main`, dernier commit) |
| Licence amont | GPL-3.0-only (`LICENSE` amont : texte de la GPL v3, sans mention « or any later version » ; pas d'en-tête de licence dans les fichiers Lua) |
| Natif Wireshark 4.6.4 | Non selon l'issue ; les dissecteurs natifs `btle` et `loratap` sont utilisés |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont). Le dossier amont `Legacy/cativity/`, sous une autre
licence, n'est pas concerné.

## Fichiers

| Fichier | Origine amont | Rôle |
|---|---|---|
| `legacy/catsniffer-rpi.lua` | `Legacy/pycatsniffer_bv3/dissectors/` | Module : en-tête Radio Packet Info (`build_catsniffer_rpi_p`) |
| `legacy/catsniffer-blepi.lua` | idem | Module : méta-en-tête BLE (`build_catsniffer_blepi_p`) |
| `legacy/catsniffer-register.lua` | idem | Point d'entrée BLE / 802.15.4 |
| `legacy/catsniffer-lora.lua` | idem | Point d'entrée LoRa |
| `catnip/lora_ascii.lua` | `catnip/protocol/` | Post-dissecteur `catnip_lora` (champ `catnip_lora.ascii`) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête de chaque fichier.

## Utilisation

- `catnip` : copier `catnip/lora_ascii.lua` dans le dossier `plugins` de
  Wireshark ; il s'applique aux captures LoRa produites par
  `catnip sniff lora -w capture.pcap` (voir `catnip/docs/wireshark.md`
  amont).
- Historique : copier **un seul** des deux points d'entrée
  (`catsniffer-register.lua` ou `catsniffer-lora.lua`) avec
  `catsniffer-rpi.lua` et `catsniffer-blepi.lua`, qu'ils chargent par
  `require`, dans le même dossier de plugins.

## Remarques

- Les deux points d'entrée historiques s'enregistrent sur la même entrée
  (valeur 147) : les charger ensemble fait que le dernier chargé l'emporte.
- Cette entrée est ajoutée à la table `dtls.port` (port DTLS 147) et non à
  une table de DLT utilisateur, alors que le commentaire amont parle de
  « User DLT » : l'accrochage aux captures DLT 147 est donc douteux (non
  vérifié dans Wireshark).
- Le chargement par `require` des modules depuis le dossier de plugins
  n'est pas vérifié ; Wireshark charge aussi ces modules comme plugins.
- Le commentaire de `catsniffer-blepi.lua` indique un usage avec le
  logiciel TI SmartRF Packet Sniffer 2 (TiWsPc2).
- Non repris : scripts Python, profils de filtres et captures d'écran.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
