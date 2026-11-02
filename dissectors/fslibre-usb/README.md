# FreeStyle Libre — protocole USB (Tidepool)

Dissecteur Wireshark Lua des rapports **USB HID** échangés avec les
lecteurs de glycémie **Abbott FreeStyle Libre** et **FreeStyle Libre Pro**,
écrit par Tidepool pour mettre au point son logiciel de téléversement.
Il décode les éléments suivants :
- l'octet de commande et la longueur ;
- les commandes texte (`0x60`, `0x21`, `0x06`, `0x35`) ;
- les trames ATP : numéros de séquence en réception et en émission,
  CRC32 ;
- les trames AAP qu'elles transportent : longueur codée sur 1 à 3 octets,
  code d'opération, données, et réassemblage sur plusieurs rapports
  (issue #515).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/tidepool-org/uploader (`lib/drivers/abbott/tools/fslibre_usb_dissector.lua`) |
| Commit importé | `4c44f03d670a52976867067890e9b0e6bedafd81` du 19/10/2026 (dernier commit de la branche par défaut `develop`) ; dernière modification du fichier : commit `a14bc7dadce139f879fdf33cea809fb500d90c25` du 11/12/2017 (« add usb id of fslibre pro ») |
| Licence amont | BSD-2-Clause, « Copyright (c) 2014-2015, Tidepool Project » (`LICENSE` du dépôt), compatible avec la licence de ce dépôt (GPL-3.0-or-later) |
| Natif Wireshark 4.6.4 | Non : seul l'USB HID générique (`usbhid`) est décodé |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563). Le reste du dépôt
(logiciel de téléversement en JavaScript) n'est pas importé.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/fslibre_usb_dissector.lua` | Protocole `fslibre_usb` (« Abbott FreeStyle Libre USB Protocol »), enregistré dans `usb.product` pour `1a61:3650` (Libre) et `1a61:3670` (Libre Pro) (lignes 281 et 284) ; il lit les 64 derniers octets de chaque paquet comme rapport HID |

## Utilisation

Copier `src/fslibre_usb_dissector.lua` dans le dossier des plugins Lua
personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »),
puis Ctrl+Maj+L. Capturer sur l'interface `usbmon` (Linux) ou USBPcap
(Windows) du lecteur **depuis son branchement**. La table `usb.product`
n'est utilisée que si le descripteur de périphérique (VID/PID) figure dans
la capture. Filtres : `fslibre_usb`, `fslibre_usb.command`,
`fslibre_usb.text`, `fslibre_usb.aap.op_code`.

## Vérification à l'import

tshark 4.6.4 (Lua 5.4) : le fichier se charge sans erreur
(`luac5.4 -p` : OK). Faute de capture réelle, rapports HID synthétiques
de 64 octets précédés de 27 octets d'en-tête, dans une capture DLT 147
associée à `fslibre_usb` par la table « User DLTs » :

| Essai | Résultat |
|---|---|
| Commande `0x05` sans données | `Command: 0x05`, `Data Length: 0` |
| Commandes texte `0x06` et `0x60` | `Text: JCGT123-T3012`, `Text: $sn?\r\n` |
| ATP de 4 octets | séquences Rx et Tx, `ATP UNKNOWN: 0x0000` |
| ATP avec AAP (longueur 3, code 0x01) | séquences et CRC32 décodés, puis **erreur Lua** ligne 90 : `attempt to index a nil value (global 'bit32')` |
| Même essai avec une copie temporaire du script précédée d'un `bit32` minimal (opérateurs Lua 5.4), copie non livrée | AAP complet décodé (`AAP Data Length: 3`, `AAP OP Code: 0x01`) ; AAP réparti sur deux rapports : `[partial][OP Code 0x2] 6 of 12 bytes`, puis réassemblé (10 octets de données) |

## Limites constatées

- **AAP non décodé sous Wireshark 4.6** : le script utilise la bibliothèque
  `bit32` de Lua 5.2 (lignes 90 à 124), absente de Lua 5.4. Toute trame
  ATP de plus de 6 octets lève une erreur Lua, et les commandes et données
  AAP (cœur du protocole) ne s'affichent pas. Sous un Wireshark lié à
  Lua 5.2, ou avec une bibliothèque `bit32` installée globalement, la
  logique fonctionne (voir le dernier essai).
- `state.processed = True` (ligne 158) : `True` est une variable globale
  non définie (`nil`), donc l'indicateur n'est jamais posé. Sans effet
  visible dans les essais.
- Réassemblage AAP indexé par l'adresse source du paquet USB : deux
  échanges entrelacés du même lecteur peuvent se mélanger.
- Colonne Info vide ; tout paquet de 64 octets ou plus du périphérique
  (y compris des réponses de contrôle) est lu comme rapport HID.
