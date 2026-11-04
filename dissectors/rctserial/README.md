# RCT Power — Serial Communication Protocol (onduleurs solaires)

Dissecteur Wireshark Lua **expérimental** (preuve de concept) du **« Serial
Communication Protocol » de RCT Power GmbH**, utilisé par les onduleurs
solaires et batteries RCT Power sur TCP 8899 : découpage des trames
(jeton de début `+`, échappement `-`), commande, identifiant d'objet (OID)
et valeur, avec une table de 895 OID nommés et typés tirée du registre de
[python-rctclient](https://github.com/svalouch/python-rctclient).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/svalouch/wireshark-rctserial-dissector |
| Commit importé | `bfe325206ac308aee62c9d9883f696c13cbba2b9` du 25/06/2022 (branche `main`, dernier commit) |
| Licence amont | GPL-3.0-only (en-têtes des fichiers : « Copyright 2021-2022 Stefan Valouch (svalouch) », `SPDX-License-Identifier: GPL-3.0-only` ; `LICENSE` amont : GPL v3) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur RCT Power natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `rctserial.lua` | Dissecteur `rctserial` (TCP 8899) |
| `rctutils.lua` | Fonctions utilitaires (décodage des types, CRC) |
| `rctdata.lua` | Table des OID (fichier généré amont) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête de chaque fichier (les en-têtes SPDX
amont sont conservées).

## Utilisation

Copier les trois fichiers `.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `rctserial`. Selon l'amont, il peut être nécessaire de passer
par « Décoder comme… » sur un flux TCP et de ne garder que `RCTSERIAL`.

## Remarques

- `rctserial.lua` charge `rctdata` et `rctutils` par `require` : les trois
  fichiers doivent être dans le même dossier du chemin de recherche Lua de
  Wireshark (non vérifié) ; Wireshark charge aussi ces deux modules comme
  plugins, ce qui est sans effet gênant a priori (variables globales).
- Limites annoncées par l'auteur : lent, bogué, **CRC non fonctionnel**
  (les erreurs de somme de contrôle sont ignorées), cas limites ignorés,
  trames réparties sur plusieurs segments TCP non gérées. Projet non
  poursuivi par l'auteur.
- Pas de capture d'exemple amont (capture d'écran non reprise) ; non
  vérifié dans Wireshark.
