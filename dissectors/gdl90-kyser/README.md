# GDL 90 — interface de données ADS-B (BrantKyser)

Dissecteur Wireshark Lua du protocole GDL 90 (« GDL 90 Data Interface
Specification », FAA / Garmin). Ce protocole est émis sur UDP par les
récepteurs ADS-B / UAT à destination des tablettes de vol (EFB). Le
script décode la trame (fanions `0x7E`, désémaphorage des octets `0x7D`,
contrôle du FCS CRC-16) puis les messages Heartbeat, Initialization,
Uplink Data, Height Above Terrain, Ownship Report, Ownship Geometric
Altitude, Traffic Report, Basic Report et le message propriétaire
uAvionix Static (`0x75`) (issue #530).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/BrantKyser/gdl90Dissector (`gdl90Dissector.lua`) |
| Commit importé | `04bb0c2e95c887152be39bd0a055633d19dfa76f` du 27/07/2021 (dernier commit de `master`) ; dernière modification du script : commit `1df3c53d2294de828a07af146eeb0830eb37be5c` du 07/05/2020 |
| Licence amont | GPLv2 (fichier `LICENSE` du dépôt, sans clause « or later » ; le script ne porte aucune mention de licence) — auteurs : Brant K. Kyser, Ryan C. Braun, Brad Walker. Déclarée `GPL-2.0-only` comme pour `dissectors/avionique` |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur GDL 90 dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/gdl90Dissector.lua` | Protocole `gdl90` (« GDL 90 », ligne 8), inscrit sur UDP 4000 (lignes 403 à 405) ; table des messages décodés (lignes 366 à 374) |

## Utilisation

`wireshark -X lua_script:src/gdl90Dissector.lua`, ou copier le fichier
dans le dossier des plugins Lua personnels de Wireshark (« Aide › À
propos de Wireshark › Dossiers »), puis recharger avec Ctrl+Maj+L.
Filtre : `gdl90`. Le port UDP 4000 est fixé dans le code (pas de
préférence) ; pour un autre port, utiliser « Décoder comme… ».

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement.
Captures synthétiques sur UDP 4000, construites d'après la spécification
GDL 90 révision A (FCS calculé avec l'algorithme de table de la
spécification) :

| Essai | Résultat |
|---|---|
| Heartbeat (GPS valide, UTC OK, horodatage 43200 s) | décodé : octets d'état, compteurs, FCS valide ; **horodatage faux** : « 108736 Seconds since 0000Z » (voir Limites) |
| Heartbeat contenant `0x7E` et `0x7D` (désémaphorage) | « Heartbeat, Stuffed, Len=13 », longueur désémaphorée 11, FCS valide |
| Heartbeat au FCS altéré | « Heartbeat, Invalid FCS » |
| Ownship Geometric Altitude (`0x0B`) | décodé : « 4000 ft. », indicateur d'alerte, facteur de mérite vertical |
| Height Above Terrain (`0x09`) | décodé : « 1200 ft. » |
| Ownship Report (`0x0A`) et Traffic Report (`0x14`) | **erreur Lua** ligne 120 (`attempt to call a nil value (field 'extract')`) : seul « Traffic Alert Status » est affiché |
| Heartbeat et Ownship Report dans un même datagramme | traités comme un seul message : « Heartbeat, Invalid FCS » |
| Heartbeat tronqué (`7E 00 81 7E`) | **erreur Lua** ligne 45 (`Range is out of bounds`) |
| Identifiant inconnu (`0x99`) | « Unknown 0x99 », FCS affiché |

## Limites constatées

- `bit.extract` n'existe pas dans la bibliothèque `bit` (BitOp) fournie
  par Wireshark : les lignes 120, 138, 141, 144, 152, 170, 222 et 227
  échouent. Ownship Report, Traffic Report (fonction commune
  `dissectTrafficReportFields`) et uAvionix Static ne sont donc pas
  décodés au-delà de leurs premiers champs. Ce sont pourtant les messages
  principaux du protocole.
- Horodatage du Heartbeat (lignes 44 à 46) : l'octet d'état 2 entier est
  décalé de 16 bits au lieu de son seul bit 7. Tout autre bit à 1 (par
  exemple « UTC OK ») fausse la valeur.
- Un seul message par datagramme : plusieurs trames GDL 90 concaténées
  dans un même paquet UDP sont lues comme une seule, avec un FCS invalide.
- Pas de contrôle de longueur : un message tronqué provoque une erreur
  Lua.
- Champs affichés en texte libre (pas de champs filtrables comme
  `gdl90.msg_id`) : seul le filtre `gdl90` est disponible.
- Pas de capture réelle disponible dans le dépôt amont.
