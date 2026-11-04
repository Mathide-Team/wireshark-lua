# CubeSat Space Protocol sur CAN (KantaTamura)

Deux post-dissecteurs Wireshark Lua du CubeSat Space Protocol (CSP),
l'un pour CSPv1 et l'autre pour CSPv2, transporté sur bus CAN en
trames étendues. Chacun décode les champs CSP de l'identifiant CAN
(source, destination, drapeaux, compteurs de fragments) et l'en-tête
CSP étendu (priorité, adresses, ports, drapeaux, longueur en v1). Il
réassemble ensuite les fragments et affiche les données du paquet CSP
(issue #536).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/KantaTamura/CSP-dissector (`cspv1_can.lua`, `cspv2_can.lua`, `sample/`) |
| Commit importé | `bf7df6454b0147f3949c8e5e492808f6e5316aee` du 10/01/2024 (dernier commit de `main`, dernière modification de `cspv1_can.lua`) ; dernière modification de `cspv2_can.lua` : commit `e6809cce249670d6154641e5bfb972408f53c79d` du 08/01/2024 ; captures : commit `da4b5792f4f6ecd418034fefc73b89376f4b214f` du 31/10/2023 |
| Licence amont | MIT (`LICENSE` amont, © 2023 Kanta Tamura ; aucune mention de licence dans les scripts). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur CSP / CubeSat dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Les scripts sont repris tels quels (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête de chacun (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/cspv1_can.lua` | Protocole `CSPv1` (« Cubusat Space Protocol version 1.0 », ligne 11) et sous-arbres en-tête CAN, en-tête étendu et données (lignes 12 à 14) ; post-dissecteur (ligne 166) |
| `src/cspv2_can.lua` | Protocole `CSPv2` (« Cubusat Space Protocol version 2.0 », ligne 11) et sous-arbres (lignes 12 à 14) ; post-dissecteur (ligne 180) |
| `captures/cspv1_can_ping.pcapng` | Capture amont `sample/cspv1_can_ping.pcapng` (4612 octets, 66 trames CAN étendues, Linux cooked v1) |
| `captures/cspv2_can_ping.pcapng` | Capture amont `sample/cspv2_can_ping.pcapng` (4356 octets, 62 trames CAN étendues, Linux cooked v1) |

## Utilisation

Copier dans le dossier des plugins Lua personnels de Wireshark (« Aide ›
À propos de Wireshark › Dossiers ») le seul script de la version voulue,
puis recharger avec Ctrl+Maj+L. On peut aussi copier les deux et
désactiver l'un dans « Analyser › Protocoles activés ». Le README amont
le précise : la version ne se déduit pas des données, et l'identifiant
CAN faisant partie du protocole, « Décoder comme » est impossible.
Filtres : `cspv1`, `csp1.src`, `csp1.xtd.dport`, `cspv2`,
`csp.destination`, `csp.source_port`.

## Vérification à l'import

`luac5.4 -p` : OK pour les deux scripts. tshark 4.6.4, chargés par `-X
lua_script:`, puis copiés dans le dossier des plugins : aucun message au
chargement.

| Essai | Résultat |
|---|---|
| `captures/cspv1_can_ping.pcapng` avec `cspv1_can.lua` | **erreur Lua** ligne 106 (`attempt to get length of a nil value`) sur 16 trames en une passe, sur les 66 avec `-2` ; aucune donnée CSP réassemblée |
| `captures/cspv2_can_ping.pcapng` avec `cspv2_can.lua` (une passe et `-2`) | **erreur Lua** ligne 106 sur les 62 trames ; aucune donnée CSP réassemblée |
| Capture synthétique SocketCAN (type de lien 227), CSPv1 en deux fragments (Begin, puis More avec Remain 0) | décodé : « Source: 1 », « Destination: 2 », « Flag: Begin (0) », « Remain: 1 », en-tête étendu (priorité 2, ports 10 et 20, « Data Length: 10 »), puis « Data: Hello, CSP » sur le dernier fragment |
| Capture synthétique SocketCAN, CSPv2 en deux fragments (Begin, puis End) | décodé : « Destination: 4360 », « Sender: 1 », « Fragment Counter », en-tête étendu (source 1, ports 10 et 20), « Data: pong, CSPv2 » |

## Limites constatées

- Les deux scripts lisent les 4 octets de l'identifiant CAN en ordre
  réseau (gros-boutiste). Dans les captures amont (Linux cooked v1),
  l'identifiant est stocké en petit-boutiste : Wireshark lit par exemple
  `00 34 10 81` comme « Ext. ID: 0x01103400 ». Les champs CSP sont donc
  faux, la reconstitution des paquets échoue et les trames provoquent
  l'erreur ligne 106. Seules les captures où l'identifiant est en ordre
  réseau (SocketCAN, type de lien 227) sont décodées. C'est ce que le
  README amont sous-entend : libpcap 1.10.2 ou plus récent est requis.
- La position de l'identifiant est calculée depuis la fin de la trame
  (`data.len`, `can.padding`) : il faut que Wireshark ait produit le
  champ `data` (pas d'autre sous-dissecteur CAN actif).
- Les deux scripts s'appliquent à toutes les trames CAN étendues, sans
  autre contrôle. Chargés ensemble, ils décodent chaque trame deux fois.
- Une trame sans début connu (capture prise en cours d'échange)
  provoque la même erreur ligne 106.
- Les données sont affichées en chaîne (`base.UNICODE`), sans dissecteur
  des services CSP (ping, etc.).
