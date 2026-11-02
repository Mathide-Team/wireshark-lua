# CHCNAV — récepteurs GNSS compatibles NovAtel (yangxin0)

Dissecteur Wireshark Lua pour le débogage des récepteurs GNSS et
centrales inertielles du fabricant chinois CHCNAV. Ces appareils parlent
le protocole NovAtel (messages ASCII `#…` et trames binaires
`AA 44 12`), plus un format binaire propre (`AA CC 48 43`). Le script
vise à résumer chaque message en une ligne de texte : heure GPS
convertie en UTC, numéro de séquence et nom du message (BESTPOS,
INSPVA, RAWIMUX, HEADING…) (issue #777).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/yangxin0/wireshark-chcnav (`chcnav.lua`) |
| Commit importé | `700aeb45a0b7d12d4c25b57f71288d0e2791dca5` du 19/07/2024 (dernier commit de la branche par défaut) ; dernière modification du script : commit `fee73b9193a1e2cf07c99dc07dfbd0bc39c5048c` du 19/07/2024 |
| Licence amont | MIT (`LICENSE` amont, © 2024 Xin Yang) ; aucune mention de licence dans le script. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur NovAtel ni CHCNAV dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/chcnav.lua` | Protocole `chcnav` (« CHCNAV Protocol », ligne 6), champ texte `chcnav.text` (ligne 7) ; table des 9 messages reconnus (lignes 67 à 77) ; détection des formats (lignes 22 à 54) ; décodeurs ASCII, CHCNAV et NovAtel (lignes 56, 177 et 200) ; boucle principale ligne 231 ; dissecteur ligne 253 ; port UDP 2200 (ligne 261) |

## Utilisation

En l'état, **le script ne se charge pas** sous Wireshark 4.6.4 (voir
ci-dessous). Une fois copié dans le dossier des plugins Lua personnels,
il est prévu pour le port UDP 2200 ; filtre `chcnav`.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins. Le dépôt amont ne contient
aucune capture. Essais sur une capture synthétique (un message ASCII
`#BESTPOSA`, une trame binaire NovAtel BESTPOS et une trame CHCNAV
`0x1201`, sur le port 2200), non commitée :

| Essai | Résultat |
|---|---|
| Chargement | **échec** : « Lua: Error during loading: chcnav.lua:141: module 'bit32' not found » ; aucun paquet n'est décodé |
| Pour aller plus loin, avec un module `bit32` de remplacement placé à part (hors de ce dépôt) | le script se charge ; les trois paquets s'affichent « CHCNAV_PROTO », puis **erreur Lua** ligne 234 (`No such method/field 'capture_len' for object type 'Tvb'`) sur chacun : aucun texte décodé |

## Limites constatées

- Ligne 141 : `require('bit32')`. Ce module de Lua 5.2 n'existe pas
  dans le Lua 5.4 de Wireshark 4.6 : le chargement s'arrête là, avant
  l'inscription sur le port 2200 (ligne 261).
- Lignes 23 et 234 : `Tvb:capture_len()` n'existe pas (c'est
  `captured_len()` ou `len()`). Même corrigée, la boucle de la ligne 234
  (`while payload:capture_len() <= 0`) ne s'exécuterait jamais pour un
  paquet non vide : le texte resterait vide.
- Autres erreurs repérées à la lecture, non atteintes à l'essai :
  `payload.bytes` au lieu de `payload:bytes` (ligne 27) et
  `payload(…).le_uint()` au lieu de `:le_uint()` (lignes 203 à 224) ;
  la boucle de la ligne 28 dépasse d'un octet ; `is_ascii_format`
  (ligne 41) exige que le premier octet soit à la fois `#`, `$` et `%`,
  ce qui est impossible ; `hc_sync_bytes:len()` (ligne 179) et `sync_bytes:len()` (ligne 202)
  appliqués à des tables Lua ; concaténation par `+` au lieu de `..`
  (ligne 246) ; `calc_crc32` lit une variable `str` inexistante
  (ligne 159) et n'est jamais appelée.
- Les analyseurs de messages (à partir de la ligne 104) ne renvoient que
  le nom du message : aucun champ (position, vitesse, attitude) n'est
  décodé, même une fois les erreurs corrigées.
- `chcnav_protocol` et `udp_table` sont des variables globales ; pas
  d'heuristique ni de préférence de port.
