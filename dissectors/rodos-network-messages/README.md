# RODOS — messages réseau du middleware (fantana21/rodos)

Dissecteur Wireshark Lua des messages réseau du middleware de RODOS
(Real time Onboard Dependable Operating System), système d'exploitation
temps réel embarqué conçu au DLR et à l'université de Wurtzbourg pour les
satellites et autres systèmes à haute fiabilité. Son middleware
publication-abonnement relie les nœuds par des passerelles ; sur UDP,
chaque message porte un en-tête `NetworkMessage` de 36 octets, que le
script décode : nœud et masque des nœuds destinataires, nombre maximal
de relais, somme de contrôle, type et longueur, nœud émetteur, heure
d'envoi, fil émetteur et identifiant du sujet (issue #822).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/fantana21/rodos (`support/tools/wireshark-dissector-network-messages.lua`) |
| Commit importé | `81072d9244e29aff24b7dd751f93a7989e0efbdf` du 14/04/2026 (dernier commit de la branche par défaut `master`) ; dernière modification du script : commit `ee10bc32f889d8e0f148c66bc12b3496cf526e17` du 02/04/2024 (« Add Python Middleware ») |
| Licence amont | Apache-2.0 : `LICENCE.txt` à la racine du dépôt (« Copyright DLR [2007 .. 2010], University Würzburg [2010 .. 2020], TU München [2020 .. 2020] », avis « Licensed under the Apache License, Version 2.0 » et rappel de la clause 3 sur les brevets) ; aucune mention dans le script, qui relève donc de la licence du dépôt. GitHub affiche « NOASSERTION » car le fichier ne reprend pas le texte complet. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur RODOS dans `tshark -G protocols` |

`LICENSE` de ce dossier est la copie conforme de `LICENCE.txt` amont
(avis et extrait) ; le texte intégral de l'Apache License 2.0 est
publié sur https://www.apache.org/licenses/LICENSE-2.0. Le script est
repris tel quel (aucune modification de code) ; seule l'en-tête de
provenance de cinq lignes est ajoutée en tête (convention du dépôt,
issue #563). Son en-tête amont le présente comme un outil de débogage
inachevé de Sebastian Kind (20/03/2024).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/wireshark-dissector-network-messages.lua` | Protocole `rodos` (« Rodos Protocol », ligne 14) ; champs `rodos.*` (lignes 17 à 26, liste ligne 29) ; dissecteur ligne 32 ; port UDP 50000 (ligne 54) |

## Utilisation

Copier le script dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`), ou le charger par
`wireshark -X lua_script:…` comme l'indique son en-tête. Le trafic du
port UDP 50000 est décodé. Filtres : `rodos`, `rodos.topic_id`,
`rodos.sender_node`, `rodos.message_type`…

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : chargement sans erreur. Le
dépôt amont ne contient aucune capture. Les champs ont été comparés à la
classe `NetworkMessage` de `api/netmsginfo.h` amont (en-tête de 36
octets, gros-boutiste) : positions, tailles et ordre des octets
concordent. Essais sur une capture synthétique (UDP 50000), non
commitée :

| Essai | Résultat |
|---|---|
| En-tête complet et 8 octets de données (nœud −1, masque `0xffffffff`, relais 10, somme `0x1234`, type 1, longueur 8, émetteur 3, heure 123456789000, fil `0x11223344`, sujet 1003) | colonne Protocole « RODOS », toutes les valeurs décodées à l'identique ; filtre `rodos.topic_id==1003` : 1 paquet |
| Paquet de 5 octets | ignoré (« UDP »), sans erreur |

## Limites constatées

- Les données utiles qui suivent l'en-tête ne sont ni affichées ni
  confiées au dissecteur `data` ; la longueur annoncée n'est pas
  comparée à la taille du paquet.
- Somme de contrôle affichée sans vérification ; valeurs en décimal
  (masque des nœuds, somme et identifiants seraient plus lisibles en
  hexadécimal) ; heure d'envoi brute, sans conversion.
- Port UDP 50000 fixe (ligne 54), sans préférence ni heuristique ; tout
  trafic de 36 octets ou plus sur ce port est décodé comme RODOS.
- Variables globales : `rodos_protocol`, les dix champs (`checksum`,
  `topic_id`…), `length` et `udp_table` (qui reçoit en fait le résultat
  de `add`, `nil`).
