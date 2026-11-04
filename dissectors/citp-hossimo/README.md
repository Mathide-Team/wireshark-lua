# CITP — échanges entre consoles lumière et serveurs de médias

Dissecteur Wireshark Lua du protocole CITP (Controller Interface Transport
Protocol), utilisé dans l'événementiel pour relier consoles lumière,
serveurs de médias et visualiseurs, écrit par Anthony Headley (hossimo).
Il décode la couche PINF (annonce des pairs sur UDP 4809, multicast
`224.0.0.180`) et la couche MSEX (serveurs de médias : informations,
bibliothèques, éléments, vignettes, état des couches) sur TCP (issue #37).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/hossimo/CITP-Dissector (`citp.lua`) |
| Commit importé | `f74005435e3bf6903248f29d866eb582ec1e69a1` du 01/11/2026 (dernier commit de la branche par défaut `master`, ajout de la licence) ; dernière modification du fichier : `24f5572782f64313f663c6857fb123fbf2647077` du 13/03/2020 |
| Licence amont | MIT, fichier `LICENSE` (« Copyright (c) 2026 Anthony Headley »), copié dans ce dossier |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur CITP dans `tshark -G protocols` |

L'issue attendait une licence (label `ATTENTE LICENSE`) : l'auteur l'a
publiée le 01/11/2026. Le fichier est repris tel quel (aucune
modification) ; seule l'en-tête de provenance de cinq lignes est ajoutée
en tête de `citp.lua` (convention du dépôt, issue #563). La capture
d'exemple du dépôt amont (`Example Capture.pcapng`) et le script
`install.sh` ne sont pas importés.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/citp.lua` | Protocole `citp` (ligne 6) et tables de ports UDP et TCP (lignes 9 et 10) ; dissecteur (ligne 89) ; fonctions d'aide : chaînes UCS-2, identifiants de bibliothèque, dimensions, types (lignes 1195 à 1246) ; ajout d'un port TCP (`CITP_add_port`, ligne 1247) ; inscription sur UDP 4809 (ligne 1265) |

## Utilisation

Copier `src/citp.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`), ou le charger par
`-X lua_script:citp.lua`. Le port TCP du serveur de médias n'est pas
fixe : le script l'inscrit quand il lit le champ « Listening Port » d'un
message PINF/PLoc. Sans ce message, l'ajouter à la main dans
Wireshark (Outils > Lua > Évaluer) : `CITP_add_port(6436)`. Le seul
filtre disponible est `citp`.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, par `-X lua_script:` et dans le
dossier des plugins : chargement sans erreur, protocole `citp` présent
dans `tshark -G protocols`. Essais sur la capture d'exemple du dépôt
amont (20 trames, non commitée) :

| Essai | Résultat |
|---|---|
| Sans le script | Trames UDP 4809 et TCP 6436 non décodées |
| Annonce PINF/PLoc du serveur (trame 1) | « CITP 1.0 >PINF >PLoc », « Listening Port: 6436 » ; port TCP 6436 inscrit, puis erreur Lua « TextWindow_new: GUI not available » (ligne 1254) |
| Trames TCP suivantes | 14 trames `citp` sur 20 : SInf (« Mbox Designer v3.10 », 6 couches), CInf, GELI, ELIn (63 bibliothèques), GEIn, LSta (6 couches détaillées), MEIn (33 éléments), GETh (« RGB8 64x64 »), ETHn |
| Annonce PINF/PLoc de la console (trame 2) | Type « LightingConsole » lu, puis erreur Lua « attempt to perform arithmetic on a nil value (global 'count') » (ligne 202) |
| Information serveur SInf (trame 3) | Produit, version et première couche DMX lus, puis la même erreur (ligne 355) |
| Segments TCP de suite d'un message (trames 14 à 19) | Non décodés (pas de réassemblage) |

## Limites constatées

- Les chaînes terminées par un octet nul sont mesurées par
  `string.find(buffer(start):string(), "\0")` (par exemple ligne 198).
  Avec Wireshark 4.6.4, `TvbRange:string()` s'arrête au premier octet
  nul : la recherche échoue et provoque une erreur Lua dès qu'une chaîne
  suit une autre (lignes 202 et 355). Le reste du message n'est alors
  pas décodé.
- L'inscription d'un port TCP ouvre une fenêtre de journal
  (`TextWindow`, ligne 1254) : sous tshark, il n'y a pas d'interface
  graphique et cela provoque une erreur Lua. Le port est quand même
  inscrit, car l'erreur survient après.
- Pas de réassemblage TCP : un message réparti sur plusieurs segments
  n'est décodé que dans le premier.
- Les indicateurs d'état de couche 0x10 et 0x20 sont testés avec
  `00000010` et `00000020` (lignes 677 et 680), lus en décimal par Lua
  (10 et 20) : ces deux états sont mal interprétés.
- Aucun champ filtrable : tout est ajouté en texte sous `citp`. Toutes
  les variables (`start`, `count`, `name`, `found_ports`…) et fonctions
  sont globales, ce qui peut entrer en conflit avec d'autres scripts.
