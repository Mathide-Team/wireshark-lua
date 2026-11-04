# OSS-7 / DASH7 Alliance Protocol (capteurs sans fil sub-GHz)

Dissecteur Wireshark Lua des trames radio **DASH7 Alliance Protocol**
(brouillon 1.0) telles que journalisées par la pile libre **OSS-7**
(University of Antwerp) : en-tête de journalisation (type de paquet, TX /
RX, horodatage, canal, classe de mot de synchronisation, puissance
d'émission ou RSSI / LQI), puis couche liaison DLL (longueur, sous-réseau,
contrôle, adresse cible, CRC), couche réseau NWL (contrôle, saut, origine
et destination, sécurité / authentification) et couche transport (contrôle
de dialogue, identifiants, gabarits d'accusé, charge utile).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/octa-connect/Octa-stack (fichier `tools/wireshark-dissector/oss7-wireshark-dissector.lua`) |
| Commit importé | `19cc45a65b5b0a5adcd37f35aa0a22e381cf519a` du 24/03/2016 (branche `master`, dernier commit ; dernière modification du dissecteur : `2fc7c7d` du 25/08/2015) |
| Licence amont | Apache-2.0 (`LICENSE` amont : avis « Copyright 2015 University of Antwerp — Licensed under the Apache License, Version 2.0 » couvrant le dépôt ; README : « © 2015-2016, University of Antwerp and others ») |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur DASH7 natif |

Le `LICENSE` amont (copié ici) ne contient que l'avis Apache-2.0 ; texte
complet de la licence : https://www.apache.org/licenses/LICENSE-2.0.

Octa-stack est une copie de la pile OSS-7 (projet DASH7 open source de
l'University of Antwerp), arrêtée en 2016 ; le dissecteur y est resté au
stade du brouillon 1.0 du protocole.

## Fichiers

| Fichier | Rôle |
|---|---|
| `oss7-wireshark-dissector.lua` | Protocole `oss7_proto` (encapsulation `wtap.USER0`) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier. Non importé : le journaliseur
Python `tools/PyLogger/` qui produit les captures.

## Utilisation

Copier `oss7-wireshark-dissector.lua` dans le dossier `plugins` de
Wireshark (ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins
Lua, puis ouvrir une capture produite par le journaliseur OSS-7 (type de
lien DLT USER0) et filtrer avec `oss7_proto`.

## Remarques

- Champ `oss7_proto.debug_var` (« test ») et description « DRAFT 1.0 test »
  hérités de l'amont : dissecteur de mise au point, non finalisé.
- Ne suit pas les révisions ultérieures du protocole DASH7 (1.1, 1.2).
- Globales `oss7_proto` et `wtap_encap` comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
