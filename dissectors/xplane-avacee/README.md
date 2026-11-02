# X-Plane UDP (Avacee)

Dissecteur Wireshark Lua heuristique du protocole UDP du simulateur de
vol X-Plane (versions 11). Il reconnaît 32 types de messages par leur
prologue de quatre lettres, sur n'importe quel port UDP : `DATA`,
`DREF`, `RREF`, `RPOS`, `RADR`, `CMND`, `BECN`, `VEHX`, `ACFN`, `ACPR`,
`ALRT`, `FAIL`/`RECO`, `ISE4`/`ISE6`, `OBJN`/`OBJL`, `SOUN`/`LSND`/
`SSND`, `SIMO`, `QUIT`/`SHUT`, etc. Les paquets `DATA` sont décodés
avec le nom de chaque groupe et de chaque valeur (issue #535). Un autre
dissecteur X-Plane 11, de wegylexy, est importé dans
`dissectors/xplane11-wegylexy/`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Avacee/XPlane-Wireshark-Dissector-Lua (`xplane.lua`) |
| Commit importé | `e2e97512554702a6d71a9dec2f03005c912e45e7` du 29/01/2021 (dernier commit de `master`) ; dernière modification du script : commit `7a73f36bd2e9dd8a8b5098cee4258df8652d99c8` du 22/11/2020 |
| Licence amont | GPL-3.0 (`LICENSE` amont : texte de la GPLv3, sans mention « or later » ni en-tête de licence dans le script). Déclarée `GPL-3.0-only` |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur X-Plane dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code, fins de ligne CRLF d'origine conservées) ; seule
l'en-tête de provenance de cinq lignes est ajoutée en tête (convention du
dépôt, issue #563). L'auteur indique dans son README que sa version en C
(Avacee/XPlane-Wireshark-Dissector-C) est plus rapide et seule suivie.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/xplane.lua` | Protocole `xplane` (« X-Plane », ligne 18) et sous-protocoles `xplane.<type>` ; préférence « BECN Port » (49707, ligne 20) ; table des messages (ligne 1786) ; contrôles de taille par type (`ValidatePacket`, ligne 1821) ; heuristique sur UDP (ligne 1868) |

## Utilisation

Copier `src/xplane.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis recharger
avec Ctrl+Maj+L. Aucun port à régler : le dissecteur s'applique dès que
le prologue est reconnu, sauf pour `BECN`, accepté seulement sur le port
de la préférence `xplane.becn_port`. Filtres : `xplane`, `xplane.rpos`,
`xplane.data`, etc.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement.
Captures synthétiques construites d'après la documentation UDP
d'X-Plane :

| Essai | Résultat |
|---|---|
| `RPOS` (UDP 49001) | décodé : longitude 7.75, latitude 48.8166, altitude, hauteur, assiette, cap, inclinaison, vitesses, taux |
| `RREF` à deux paires | « Count = 2.0 », deux entrées avec identifiant et valeur |
| `DATA` à deux groupes (index 3 et 0) | « Speeds » avec « Knots Indicated Airspeed », « Knots True Airspeed », etc. ; « Frame Rate Info » |
| `DATA` d'index inconnu (999) | **erreur Lua** ligne 1392 (`attempt to index a nil value`) |
| `CMND` | « Command: sim/operation/pause_toggle » |
| `RPOS` de demande (6 octets) | « Request Positional Data », fréquence |
| `BECN` sur UDP 49707 | décodé : versions, « Host ID », « Version Number: 115101 », « Role: Master (1) », port, nom de machine, nouveau port |
| `BECN` sur UDP 49001 | refusé (port différent de la préférence), reste en UDP |
| `RADR` à deux points | « Weather Radar (OUT) », « Count = 2.0 », longitude, latitude, précipitations (40 et 80) et sommet de chaque point |
| Charge utile `HELLO world`, datagrammes de 2 et 4 octets | non revendiqués, restent en UDP, sans erreur |

## Limites constatées

- `DATA` : un index absent de la table interne provoque une erreur Lua
  (ligne 1392). C'est le cas d'index propres à une version ou ajoutés
  par la suite.
- L'heuristique ne contrôle que le prologue (et la taille pour quelques
  types). Tout datagramme UDP commençant par `DATA`, `RPOS`, `CMND`,
  etc. est revendiqué, quel que soit le port.
- La préférence `controlpad_port`, citée par le contrôle `ACFN`
  (ligne 1827), n'est jamais déclarée : ce contrôle est sans effet.
- Les compteurs sont affichés en flottants (« Count = 2.0 »).
- Pas de capture réelle dans le dépôt amont.
