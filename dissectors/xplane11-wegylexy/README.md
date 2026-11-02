# X-Plane 11 UDP (wegylexy)

Dissecteur Wireshark Lua du protocole UDP du simulateur de vol X-Plane 11.
Le message est reconnu par son prologue de quatre lettres suivi d'un
octet nul. Quatre messages sont décodés (issue #534) :

- `BECN` : balise de découverte (version, application, rôle, port, nom
  de machine) ;
- `RPOS` : position de l'avion (longitude, latitude, altitude MSL et AGL,
  assiette, cap, inclinaison, vitesses et taux de rotation) ;
- `RADR` : points du radar météo ;
- `RREF` : valeur d'une référence de données (dataref).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/wegylexy/xplane11-dissector (`xp11.lua`) |
| Commit importé | `08658938dc910d6139e1100974d5fdc69c8d8917` du 16/10/2018 (dernier commit de `master`, qui est aussi la dernière modification du script) |
| Licence amont | MIT (`LICENSE` amont, © 2017 TimTim ; aucune mention de licence dans le script). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur X-Plane dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code, fins de ligne CRLF d'origine conservées) ; seule
l'en-tête de provenance de cinq lignes est ajoutée en tête (convention du
dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/xp11.lua` | Protocole `xp11` (« X-Plane 11 », ligne 6), sous-protocoles `xp11.becn`, `xp11.rpos`, `xp11.radr` et `xp11.rref` (lignes 9, 18, 33 et 39) ; table des messages (lignes 71, 102, 126 et 144) ; inscrit sur UDP 49001 (ligne 164) |

## Utilisation

Copier `src/xp11.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis recharger
avec Ctrl+Maj+L. Filtres : `xp11`, `xp11.prolog == "RPOS"`,
`xp11.rpos.lat`, `xp11.becn.name`. Le port 49001 est fixé dans le code.
Pour le port 49000 (données reçues par X-Plane) ou la balise multicast
49707, utiliser « Décoder comme… ».

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement.
Captures synthétiques sur UDP 49001, construites d'après le code et la
documentation UDP d'X-Plane :

| Essai | Résultat |
|---|---|
| `RPOS` (lon 7,75, lat 48,8166, 1200 m, vitesses 60 / 1 / −60 m/s) | décodé : « E7°45.0' », « N48°48.996' », « 3937.0078740157 ft MSL », assiette, cap, « Linear Velocity: 45°/164 kt, +3 fpm », taux de rotation |
| `RADR` avec deux points | décodé : deux points avec position, précipitations (40 % et 80 %) et sommet |
| `RREF` (n° d'écho 3, valeur 0,5) | « Data Reference: 0.5 » ; « Echo Number: 4.2039e-45 » (voir Limites) |
| `BECN` (version 113000) | octets de version, application, numéro de version, puis **erreur Lua** ligne 97 (`bad argument #2 to 'format' (number has no integer representation)`) |
| `DATA` (prologue non géré) | **erreur Lua** ligne 159 (`attempt to call a nil value`) |
| Datagramme de 2 octets | **erreur Lua** ligne 154 (`Range is out of bounds`) |

## Limites constatées

- `BECN` : sous Lua 5.4, `string.format("%d", version / 10000)` échoue
  dès que la version n'est pas un multiple de 10000, c'est-à-dire pour
  presque toutes les versions réelles (ligne 97). Le rôle, le port et le
  nom de machine ne sont alors pas affichés.
- Les prologues non gérés (`DATA`, `DREF`, `CMND`, `VEHX`, etc.)
  provoquent une erreur Lua : il n'y a pas de repli (ligne 159).
- `RREF` : le numéro d'écho est déclaré en `float` au lieu d'un entier,
  donc la valeur affichée est fausse. Seule la première paire est
  décodée, alors qu'un `RREF` en contient souvent plusieurs.
- `RPOS` : la plage du sous-arbre ne couvre que 16 octets (ligne 104).
  Les sous-arbres `RPOS`, `RADR` et `RREF` sont ajoutés à la racine,
  hors de l'arbre `xp11`.
- Pas de contrôle de longueur ; un seul port (49001).
- Pas de capture réelle dans le dépôt amont.
