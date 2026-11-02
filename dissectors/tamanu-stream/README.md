# Tamanu — flux de synchronisation `application/json+frame`

Dissecteur Wireshark Lua (post-dissecteur) des réponses HTTP en flux du
serveur central de [Tamanu](https://github.com/beyondessential/tamanu)
(dossier patient électronique de BES) : il découpe le corps des réponses
`Content-Type: application/json+frame` en messages `CR+LF`, type (u16),
longueur (u32), puis données JSON. Il affiche les types connus
(`SESSION WAITING`, `PULL WAITING`, `PULL CHANGE`, `END`) (issue #517).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/beyondessential/tamanu (`docs/wireshark-tamanu-stream.lua`) |
| Commit importé | `7672b1b4cd0548ef9639051d2b5356113360dafd` du 02/11/2026 (dernier commit de `main`) ; dernière modification du fichier : commit `2d0e73e5a48bd635101c466c08cbe3c49a232b53` du 07/10/2025 (Daniel Nash) |
| Licence amont | Double licence du dépôt. D'après `COPYRIGHT`, le projet est sous GPL-3.0 ou ultérieure (`LICENSE-GPL`), sauf les API et intégrations FHIR. Celles-ci sont sous BSL 1.1 (`LICENSE-BSL`) et listées explicitement (`packages/database/src/models/fhir`, `packages/central-server/app/hl7fhir`, etc.). `docs/` n'en fait pas partie : le fichier est donc sous GPL-3.0-or-later, comme ce dépôt. `package.json` déclare « GPL-3.0-and-later AND BUSL-1.1 » pour l'ensemble |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur Tamanu dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE-GPL` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/wireshark-tamanu-stream.lua` | Protocole `tamanu.stream` (« Tamanu stream »), post-dissecteur (ligne 81) ; champs `tamanu.message`, `tamanu.kind`, `tamanu.length`, `tamanu.data` |

## Utilisation

Copier `src/wireshark-tamanu-stream.lua` dans le dossier des plugins Lua
personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »),
puis Ctrl+Maj+L. Le trafic doit être décodé en HTTP : port HTTP connu, ou
`Decode As…` (par exemple `-d tcp.port==3000,http`). En HTTPS, il faut
aussi les clés TLS. Filtres : `tamanu.stream`, `tamanu.kind == 0x0003`.

## Vérification à l'import

tshark 4.6.4 : le fichier se charge sans erreur (`luac5.4 -p` : OK).
Captures synthétiques construites au format produit par le serveur
(`packages/central-server/app/sync/StreamMessage.js`, lignes 3 à 27 ;
types dans `packages/constants/src/sync.ts`, au commit importé) :

| Essai | Résultat |
|---|---|
| Réponse `Content-Length` avec 4 messages (`0x0001`, deux `0x0003` avec JSON, `0xf001`) | `Tamanu stream (4 messages)` : types décodés, longueurs et données JSON exacts ; filtre `tamanu.kind == 3` : OK |
| Réponse `Transfer-Encoding: chunked` (comme le serveur), un message par bloc, segments TCP séparés | `Tamanu stream (3 messages)` sur la trame qui termine la réponse |
| Longueur annoncée (100) supérieure aux données restantes | **erreur Lua** ligne 63 (`Range is out of bounds`) |

## Limites constatées

- **Aucun contrôle de longueur** : une longueur annoncée trop grande ou
  des octets de fin incomplets (réponse tronquée, capture coupée)
  provoquent une erreur Lua (lignes 53 à 63) au lieu d'un avertissement.
- Les deux octets `CR+LF` sont sautés sans vérification (ligne 53).
- Rien n'est affiché tant que la réponse HTTP n'est pas complète
  (`http.file_data` n'est fourni qu'une fois le flux réassemblé). Un flux
  interrompu n'est donc pas décodé.
- Le type de contenu doit valoir exactement `application/json+frame`
  (ligne 40) : un paramètre (`; charset=…`) le fait ignorer.
- Le post-dissecteur s'exécute sur toutes les trames ; colonnes Protocole
  et Info laissées à HTTP.
- Pas de capture réelle disponible (le trafic de production passe en
  HTTPS).
