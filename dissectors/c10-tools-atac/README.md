# IRIG 106 Chapter 10 sur UDP (atac/c10-tools)

Dissecteur Wireshark Lua des paquets de télémesure IRIG 106 Chapter 10
transportés sur UDP selon le Chapter 10 / 11. Il vient de la boîte à
outils Python c10-tools d'Avionics Test and Analysis Corporation (ATAC).
Il décode l'en-tête de transport UDP (version, type de message, numéro
de séquence), puis l'en-tête du paquet Chapter 10 : motif de
synchronisation `0xEB25`, canal, longueurs, version, séquence,
drapeaux, type de données, compteur de temps relatif et somme de
contrôle (issue #532).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/atac/c10-tools (`c10_tools/wireshark_dissector.lua`) |
| Commit importé | `1562de718a92f4c4e0e30b4e6673dd9108f7077c` du 15/06/2022 (dernier commit de `master`) ; dernière modification du script : commit `1570135df507aea98a76b278efbdd1aa81537626` du 18/08/2020 |
| Licence amont | BSD-3-Clause (`LICENSE.txt` amont, © 2019 Avionics Test and Analysis Corporation ; aucune mention de licence dans le script). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur IRIG 106 / Chapter 10 dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE.txt` de ce dossier (copie
conforme du `LICENSE.txt` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/wireshark_dissector.lua` | Protocole `c10` (« Chapter 10 », ligne 44), inscrit sur UDP 2000 (variable globale `target_port`, ligne 15 ; inscription lignes 88 et 89) ; contrôle du motif de synchronisation ligne 51 |

## Utilisation

Copier `src/wireshark_dissector.lua` dans le dossier des plugins Lua
personnels de Wireshark (« Aide › À propos de Wireshark › Dossiers »),
puis recharger avec Ctrl+Maj+L, ou lancer `wireshark -X
lua_script:src/wireshark_dissector.lua`. Filtre : `c10`. Pour un autre
port que 2000, utiliser « Décoder comme… » (pas de préférence).

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement.
Essai sur la capture de test amont `tests/test.pcap`. Elle n'est pas
copiée ici : elle fait 1 048 576 octets et elle est tronquée (« cut
short in the middle of a packet » après 1020 paquets). Elle contient
1020 datagrammes UDP 62360 → 2000 :

| Essai | Résultat |
|---|---|
| 5 datagrammes au format de transport non segmenté (premier octet `0x01`) | tous décodés : en-tête de transport, « Sync Pattern: 0x25eb », canal, longueurs, « Data Type: 0x11 (Time data format 1) », « 0x00 (Computer Generated data format 0) », « 0x19 (Mil-STD-1553 data format 1) », compteur de temps relatif, somme de contrôle |
| 1014 datagrammes segmentés (premier octet `0x11`, en-tête de transport de 12 octets) | non décodés : le motif `25eb` n'est pas à l'octet 4, le script rend 0 (seule la colonne Protocole passe à « Chapter10 ») |
| Datagramme de 4 octets `01 43 01 00` (trame 324, en-tête de transport seul) | **erreur Lua** ligne 51 (`Range is out of bounds`) |

## Limites constatées

- Les paquets segmentés (type de message 1, « Todo » de l'amont ligne
  63) ne sont pas pris en charge ; dans la capture amont, c'est la
  quasi-totalité du trafic.
- Les données du paquet (corps Time, 1553, PCM, etc.) ne sont pas
  décodées : seul l'en-tête Chapter 10 de 24 octets l'est. L'en-tête
  secondaire et la somme de contrôle ne sont pas vérifiés.
- La colonne Protocole passe à « Chapter10 » avant le contrôle du motif
  de synchronisation, même pour les paquets refusés.
- Le script définit des variables globales (`target_port`,
  `data_types`, `format`, `udp_table`). Elles peuvent entrer en
  collision avec d'autres scripts Lua.
- Pas de contrôle de longueur : un datagramme de moins de 6 octets
  provoque une erreur Lua.
- Champs affichés en texte libre (pas de champs filtrables) : seul le
  filtre `c10` est disponible.
