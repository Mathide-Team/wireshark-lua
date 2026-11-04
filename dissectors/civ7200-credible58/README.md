# CI-V IC-7200 — commande de l'émetteur-récepteur ICOM IC-7200 (USB)

Postdissecteur Wireshark Lua du protocole CI-V d'ICOM, dans la variante
de l'émetteur-récepteur IC-7200, écrit par credible58 (« pjo »). Il lit
les messages CI-V (délimiteurs `FE FE` … `FD`) transportés dans les
transferts USB « bulk » entre l'ordinateur et le poste, et affiche
adresses, commande, sous-commande, fréquence, mode et filtre (issue #952).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/credible58/civ7200 (`civ7200.lua`) |
| Commit importé | `79c54199ce818e40cd18ff35ab72b2094f6355a8` du 16/02/2020 (dernier commit de la branche par défaut `master`) ; dernière modification du fichier : `135d49bdc838abda32c1b364cac9e9396b8aa3f8` du 26/12/2019 |
| Licence amont | GNU GPL v3, indiquée dans l'en-tête du fichier (« License - GNU GPL v3 », lignes 11 et 12), sans mention « ou ultérieure » : `GPL-3.0-only` ; pas de fichier de licence dans le dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur CI-V dans `tshark -G protocols` |

Le dépôt amont ne fournit pas de fichier de licence : le fichier `LICENSE`
de ce dossier est le texte officiel de la GNU GPL v3
(https://www.gnu.org/licenses/gpl-3.0.txt), ajouté pour accompagner le
fichier importé. Le fichier est repris tel quel (aucune modification ;
espaces en fin de ligne conservés) ; seule l'en-tête de provenance de
cinq lignes est ajoutée en tête de `civ7200.lua` (convention du dépôt,
issue #563). La capture d'exemple du dépôt amont
(`Icom IC-7200 Rig Control Error.zip`, 47 Mo décompressée) n'est pas
importée.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/civ7200.lua` | Tables de valeurs (lignes 25 à 127) ; champs USB lus (lignes 131 à 139) ; protocole `civ7200` (ligne 142) et ses champs (lignes 144 à 164) ; inscription comme postdissecteur (ligne 171) ; table des commandes (ligne 174) ; détection d'un message CI-V (ligne 208) ; décodage BCD de la fréquence (ligne 239) ; dissecteur (ligne 274) |

## Utilisation

Copier `src/civ7200.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`), ou le charger par
`-X lua_script:civ7200.lua`, puis ouvrir une capture USB (USBPcap ou
usbmon) du câble de commande du poste. Le décodage n'a lieu qu'au
second passage (`pinfo.visited`, ligne 295) : avec tshark, utiliser
l'option `-2` ; dans Wireshark, il apparaît une fois la capture chargée.
Filtres : `civ7200`, `civ7200.cmd`, `civ7200.frequency`,
`civ7200.opmode`, `civ7200.filtset`…

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, par `-X lua_script:` et dans le
dossier des plugins : chargement sans erreur, protocole `civ7200`
présent dans `tshark -G protocols`. Essais sur la capture d'exemple du
dépôt amont (196 059 trames USB, 430 s), non commitée, et sur une
capture synthétique non commitée :

| Essai | Résultat |
|---|---|
| Capture amont, un seul passage | Aucune trame `civ7200` (décodage réservé au second passage) |
| Capture amont, `tshark -2`, par `-X lua_script:` et dans le dossier des plugins | 4 543 trames `civ7200`, aucune erreur Lua |
| Lecture de la fréquence (commande 0x03) | « CI-V Cmd: Read operating frequency », « CI-V Echo: … », « CI-V Rsp: Read operating frequency: 28078000 » ; `civ7200.frequency` vaut 28078000, 18104000 ou 14226450 |
| Lecture du mode (0x04) | « CI-V Rsp: Read operating mode: USB mode/Wide » |
| Sous-commandes (0x07, 0x1A, 0x1C) | « Select VFO mode:Select VFO A », « Send and read operations:Send/read DATA mode », « Send/read transceiver status:… » |
| Acquittement du poste | 25 trames « CI-V Ack » |
| Trame UDP synthétique (charge `FE FE 70 E0 03 FD`), `tshark -2` | Erreur Lua « attempt to index a nil value » (ligne 223), sur chaque trame non USB |

## Limites constatées

- Sur toute trame qui n'est pas un transfert USB, `usb.data_len` est
  absent et le script provoque une erreur Lua (ligne 223) : chargé en
  permanence, il ajoute une erreur à chaque trame des autres captures,
  au second passage.
- Rien n'est décodé au premier passage (ligne 295) : tshark sans `-2`
  n'affiche rien.
- Seul le CI-V sur USB est pris en charge, pas les liaisons série ni le
  CI-V transporté sur le réseau.
- Pour les commandes qui ont une sous-commande mais pas de table
  (0x08, 0x0E, 0x0F, 0x10, 0x13, 0x14, 0x15, 0x16), le champ et la
  table valent 0 (lignes 350 à 355) : erreur Lua prévisible à la
  lecture du code, non rencontrée dans la capture amont.
- Les trois champs de sous-commande portent le même nom
  `civ7200.subcmd` (lignes 149 à 151) ; l'alerte `civ7200.invalid`
  (ligne 167) n'est jamais émise.
- Toutes les variables et fonctions sont globales (`civ_length`,
  `cmd_table`, `getCivLength`…), ce qui peut entrer en conflit avec
  d'autres scripts. Le script utilise la bibliothèque `bit` fournie par
  Wireshark (ligne 252).
