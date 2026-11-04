# EnOcean ESP3 (EnOcean Serial Protocol 3 sur TCP/UDP)

Post-dissecteur Wireshark Lua de l'**EnOcean Serial Protocol 3 (ESP3)**,
format série des passerelles et clés USB EnOcean (capteurs et interrupteurs
domotiques sans pile, 868/902/928 MHz), lorsqu'il est relayé sur TCP ou
UDP : octet de synchronisation 0x55, longueur des données, longueur
optionnelle, type de paquet, CRC8 d'en-tête, puis décodage des types
**RADIO_ERP1** (1) et **RADIO_ERP2** (10) — contrôle d'adresse, en-tête
étendu, type de télégramme (R-ORG), identifiants source / destination,
données, statut, nombre de sous-télégrammes, RSSI (dBm), niveau de
sécurité.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/gisaki/ESP3_Wireshark_Dissector (fichier `esp3.lua`) |
| Commit importé | `c02d96bfd896c712989ec0a1a666d7520e32a164` du 16/10/2017 (branche `master`, dernier commit, qui modifie aussi le dissecteur) |
| Licence amont | MIT (`LICENSE` amont, © 2017 gisaki) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur EnOcean / ESP3 natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `esp3.lua` | Post-dissecteur `esp3` |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `esp3.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `esp3`. Si la passerelle ajoute un en-tête propre avant les
données ESP3, régler la variable `YOUR_EXTRA_HEADER_SIZE` en tête du
fichier (modification locale).

## Remarques

- **Hypothèses fortes sur la trame** : le décalage est calculé en dur pour
  Ethernet (14 octets) + IPv4 + TCP sans options (20 octets) ou UDP ;
  IPv6, VLAN, options TCP ou captures Wi-Fi / « Linux cooked » décalent
  l'analyse. Le post-dissecteur examine tous les paquets TCP/UDP et ne
  retient que ceux qui commencent par 0x55 avec un type 1 ou 10.
- Les fonctions `analyze_esp3`, `decode_esp3`… sont définies (en
  globales) **à l'intérieur** de la fonction de dissection, après leur
  premier appel : le tout premier paquet TCP/UDP peut provoquer une erreur
  Lua (« attempt to call a nil value »), les suivants étant décodés
  normalement (non vérifié).
- **`bit32` absent des Wireshark récents** : le décodage des bits d'en-tête
  appelle `bit32.band` / `bit32.rshift`, bibliothèque de Lua 5.2 absente par
  défaut de Lua 5.3 et 5.4, seules versions prises en charge depuis
  Wireshark 4.4 (qui fournit `bit` à la place). Contournement local :
  ajouter `bit32 = bit` en tête du fichier (code amont non modifié ici).
- Le CRC8 n'est pas vérifié ; les profils EEP (signification des données
  selon le capteur) ne sont pas décodés.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
