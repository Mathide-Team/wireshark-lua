# OSCAR / ICQ — messagerie instantanée

Dissecteur Wireshark Lua du protocole **OSCAR** utilisé par ICQ (et AIM),
d'après la description http://iserverd.khstu.ru/oscar/ :

- `flapp` : suite de paquets FLAP dans un segment TCP (port 5190) ;
- `flap` : en-tête FLAP (canal, numéro de séquence, longueur) ;
- `snac` : familles / sous-types SNAC ;
- `uib`, `uibtlv` : blocs d'informations utilisateur (TLV) ;
- `icqumsg` / `icqsmsg` : messages texte utilisateur → serveur et
  serveur → utilisateur, avec le texte décodé.

Filtre pour afficher les messages : `icqsmsg || icqumsg`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/luc-lynx/icq-dissector (fichier `oscar.lua`) |
| Commit importé | `9a1ecd72a0e510957ce41a89521e3faf23f3da09` du 12/01/2016 (branche `master`, dernier commit, qui est aussi la dernière modification de `oscar.lua`) |
| Licence amont | GPL-3.0-or-later d'après l'en-tête du fichier (« Copyright (C) 2016 Evgeny Sidorov » ; « either version 3 of the License, or (at your option) any later version ») — voir ci-dessous |
| Natif Wireshark 4.6.4 | Oui en partie — dissecteur natif `aim` (OSCAR, TCP 5190) et `icq` (ancien protocole UDP 4000) |

**Licence : incohérence amont.** Le fichier `LICENSE` du dépôt amont
(licence GitHub « GPL-2.0 ») est le texte de la GPL v2, alors que
l'en-tête de `oscar.lua`, seul fichier de code, accorde la GPL v3 ou
ultérieure. L'en-tête, déclaration explicite de l'auteur pour ce fichier,
est retenu (`GPL-3.0-or-later`, compatible avec la GPL v3 du dépôt) ; le
`LICENSE` amont (GPL v2) est conservé ici tel quel pour traçabilité. Le
texte de la GPL v3 est celui du `LICENSE` à la racine de ce dépôt.

## Fichiers

| Fichier | Rôle |
|---|---|
| `oscar.lua` | Protocoles `flapp`, `flap`, `snac`, `uib`, `uibtlv`, `icqumsg`, `icqsmsg` ; `flapp` sur TCP 5190 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `oscar.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `flap`, `snac` ou `icqsmsg || icqumsg`.

## Remarques

- Doublon partiel du dissecteur natif `aim`, plus complet pour OSCAR :
  ce script prend le port TCP 5190 à sa place ; son intérêt est
  l'extraction directe du texte des messages ICQ.
- Script de 2016 : les serveurs ICQ / OSCAR historiques ont fermé ; utile
  pour des captures anciennes ou des serveurs compatibles. Les connexions
  chiffrées (TLS) ne sont pas lisibles.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
