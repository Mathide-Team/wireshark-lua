# Orion — protocole public des nacelles caméra Trillium

Dissecteur Wireshark Lua du protocole public Orion de Trillium
Engineering (nacelles gyrostabilisées Orion). Il découpe les paquets
`0xD0 0x0D`, identifiant, longueur, données, somme de contrôle. Une même
trame peut en contenir plusieurs. Les champs de près de 100 types de
paquets sont décodés : commandes de pointage, versions logicielles,
GPS, INS, réglages caméra, suivi, enregistrement vidéo, réseau… (issue
#526).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/trilliumeng/orion-sdk (`wireshark/OrionPublic.lua`, `wireshark/OrionPublic_packet.lua`) |
| Commit importé | `dde2e42a646e22a38d723d31ab3e5c185035ae20` du 22/07/2026 (dernier commit de `master`) ; dernière modification des deux fichiers : commit `0576a327d735bc31dbf2b270f6e03f109e9d5967` du 22/07/2026 |
| Licence amont | MIT : `License.txt` du dépôt (« Copyright (c) 2013-2018, Trillium Engineering, LLC »). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur Orion dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `License.txt` amont). Les scripts sont repris tels quels
(aucune modification de code) ; seule l'en-tête de provenance de cinq
lignes est ajoutée en tête de chacun (convention du dépôt, issue #563).
`OrionPublic.lua` est produit par l'outil ProtoGen à partir de l'ICD
public ; `OrionPublic_packet.lua` est écrit à la main d'après le
`Readme.md` amont.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/OrionPublic_packet.lua` | Protocole `OrionPublic` (« Orion Protocol », ligne 88), champs `OrionPublic.id`, `.packet`, `.length`, `.time`, en-tête et ports UDP 8745, 8746, 8748 et TCP 8747 (lignes 158 à 161) |
| `src/OrionPublic.lua` | Tables d'énumérations et fonctions de décodage par type de paquet ; charge le précédent par `require("OrionPublic_packet")` (ligne 8) ; `OrionPublic.dissector` (ligne 5859) |

## Utilisation

Comme l'indique le `Readme.md` amont : copier les **deux** fichiers de
`src/` dans un sous-dossier `OrionPublic` du dossier des plugins Lua
personnels (« Aide › À propos de Wireshark › Dossiers »). Redémarrer
ensuite Wireshark. Filtres : `OrionPublic`, `OrionPublic.id == 1`,
`OrionPublic.packet == "ORION_PKT_CMD"`.

## Vérification à l'import

`luac5.4 -p` : OK pour les deux fichiers. tshark 4.6.4, fichiers placés
dans `plugins/OrionPublic/` : chargement sans erreur. Paquets
synthétiques construits d'après `Utils/TrilliumPacket.c` (somme de
Fletcher modulo 251) :

| Essai | Résultat |
|---|---|
| TCP 8747, `ORION_PKT_CMD` (pan 1000, tilt −500, mode 2, stabilisé, impulsion 5) | `OrionCmd` : `Pan: 1 rad (57.29577951 deg)`, `Tilt: -0.5 rad`, `Mode: Unknown Value ( 2 )`, `Stabilized: 1`, `ImpulseTime: 0.5 seconds` |
| Même segment : requête `ORION_PKT_CROWN_VERSION` vide + `ORION_PKT_CMD` | Info « OrionCrownVersion[R], OrionCmd » : deux paquets décodés |
| Identifiant inconnu `0xfa` | « Unknown packet ID 0xfa » et données brutes |
| Paquet tronqué (7 octets sur 13) | **erreur Lua** `OrionPublic_packet.lua:132` (`Range is out of bounds`) |
| UDP 8745, `ORION_PKT_CMD` | décodé comme en TCP |
| Chargement par `-X lua_script:OrionPublic.lua` (hors dossier des plugins) | en-tête reconnu, mais **erreur Lua** `OrionPublic_packet.lua:146` (`get_OrionPktType_t_string` nil) |

## Limites constatées

- Les deux fichiers doivent être installés ensemble, comme plugins :
  chargés par `-X lua_script:`, le décodage échoue.
- La somme de contrôle n'est ni vérifiée ni affichée ; aucun contrôle
  de longueur (erreur Lua sur paquet tronqué, et donc sur un paquet
  réparti sur deux segments TCP, faute de réassemblage).
- Identifiants en double dans l'aiguillage généré : seule la première
  variante est décodée. C'est le cas pour `1` (`OrionCmd`, jamais
  `OrionCmdExtended` ni la réponse, lignes 5789 à 5791), `228` (lignes
  5828 et 5829) et `98` (lignes 5831 et 5832).
- Le `Readme.md` amont signale des types encore « non optimisés »
  (Orion Path, TLE Detects).
- Nombreuses fonctions et variables globales ; pas de capture réelle
  disponible.
