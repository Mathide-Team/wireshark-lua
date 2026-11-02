# IPND — découverte de voisins des réseaux tolérants aux délais (rohieb)

Dissecteur Wireshark Lua d'IPND (IP Neighbor Discovery), protocole de
découverte de voisins des réseaux tolérants aux délais et aux ruptures
(DTN, « Internet interplanétaire ») décrit par les brouillons
`draft-irtf-dtnrg-ipnd` de l'IRTF. Les nœuds DTN diffusent des balises
sur UDP 4551 qui annoncent leur identifiant (EID) et leurs services
(couches de convergence TCPCL, UDPCL…). Le script décode la version 2
des balises : drapeaux, numéro de séquence, EID et bloc de services à
longueurs SDNV (issue #781).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/rohieb/wireshark-ipnd-dissector (`ipnd.lua`) |
| Commit importé | `0ea78bc664cbb8d087e45691143a6c70542dd404` du 23/05/2016 (seul commit du dépôt, « first version: parses v2 services and EIDs, no NBFs yet ») ; c'est aussi la dernière modification de `ipnd.lua` |
| Licence amont | BSD-2-Clause : texte de la licence en tête du script (lignes 9 à 32 du fichier importé), « Copyright (c) Roland Hieber ». Le dépôt ne contient pas de fichier de licence séparé. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : Wireshark décode Bundle Protocol (`bundle`, `bpv7`), BPSec et TCPCL, mais aucun dissecteur IPND dans `tshark -G protocols` |

Le texte de la licence BSD-2-Clause, avec la mention de copyright, est
conservé dans l'en-tête du script, qui reste la seule source amont de la
licence : aucun fichier `LICENSE` n'est créé ici (le validateur l'accepte
avec un avertissement). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/ipnd.lua` | Protocole `ipnd` (« IP Neighbor Discovery », ligne 37) ; alertes expertes (lignes 43 à 50) ; champs `ipnd.*` (lignes 56 à 81) ; décodage SDNV et chaînes (lignes 89 à 158) ; services (ligne 161) ; versions 1, 2 et 3 (lignes 197, 202 et 262) ; dissecteur ligne 274 ; port UDP 4551 (lignes 292 et 293) |

## Utilisation

Copier `src/ipnd.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`). Le trafic du port UDP 4551 est
décodé. Filtres : `ipnd`, `ipnd.version`, `ipnd.seqno`, `ipnd.eid`,
`ipnd.flags.has_eid`, `ipnd.flags.has_service_block`…

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : chargement sans erreur. Le
dépôt amont ne contient aucune capture. Essais sur une capture
synthétique (UDP 4551), non commitée :

| Essai | Résultat |
|---|---|
| v2, EID `dtn://node1` et service `tcpcl` / `port=4556` | drapeaux, séquence 1, « EID: dtn://node1 », « Service: tcpcl, params: port=4556 » |
| v2, EID de 156 caractères (longueur SDNV sur 2 octets) | EID décodé en entier, « String Length: 156 » |
| v2, 2 services annoncés, 1 seul présent | premier service décodé, puis « Service Name: [error] » et alerte « Insufficient bytes remaining in packet » |
| v2, SDNV tronquée (`80 80`) | « EID: [error] », erreur experte « Malformed SDNV » |
| v2, longueur d'EID 32 pour 3 octets | « EID: [error] », alerte « Insufficient bytes remaining in packet » |
| v1 et v3 | seule la version est affichée, sans alerte |
| Version 7 | alerte « Unknown Version » |
| v2 avec filtre de Bloom (drapeau 0x04) | drapeau affiché, octets du filtre ignorés |
| Champs | `ipnd.eid` = « String Value: dtn://node1 » ; `ipnd.service_name` = `537472696e,537472696e67205661` ; `ipnd.service_param` absent ; filtre `ipnd.eid contains "node1"` : 1 paquet |

## Limites constatées

- Versions 1 et 3 non décodées (fonctions vides, lignes 197 à 199 et
  262 à 263) ; filtre de Bloom des voisins (NBF) de la version 2 non
  décodé (ligne 257, « FIXME »).
- Ligne 155 : la valeur des champs est remplacée par le texte
  « String Value: … ». Pour `ipnd.eid` (chaîne), le champ vaut
  « String Value: dtn://node1 » ; pour les noms de services (champ
  d'octets), il contient les codes hexadécimaux des premiers caractères
  de ce texte (`537472696e` = « Strin ») au lieu du nom.
- Les paramètres de service sont rangés dans `ipnd.service_name`
  (ligne 179) : `ipnd.service_param` n'est jamais rempli.
- `ipnd.fields` (ligne 78) cite `pf_eid_len`, jamais définie ; sans
  effet constaté. `pf_beacon_len` est déclaré mais pas utilisé.
- Variables globales `ipnd` et `udp_table`.
