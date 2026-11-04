# Motorola XCMP / XNL — gestion des radios MOTOTRBO

Dissecteurs Wireshark Lua de deux protocoles Motorola **MOTOTRBO** :

- `xnl.lua` : protocole `xnl` (« Motorola XNL », couche réseau) — longueur,
  opcode (statut maître, demande / réponse de clé d'authentification,
  connexion, carte système, données, acquittement…), protocole encapsulé,
  adresses source / destination, transaction, et détails des messages
  de contrôle ; port TCP 8002 ; crée la table `xnl.proto` ;
- `xcmp.lua` : protocole `xcmp` (« Motorola XCMP », Extended Command and
  Management Protocol) transporté par XNL (`xnl.proto` = 1) — opcode et
  transaction dans la colonne Info, détail de plusieurs commandes (statut
  radio, initialisation du périphérique, contrôle à distance, sélection
  canal / zone, balayage, contrôle d'appel…).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/george-hopkins/xcmp-xnl-dissector |
| Commit importé | `bb39f2a22cb6ae3895de07f2295d8f48f14093ee` du 17/07/2017 (branche `master`, dernier commit ; dernières modifications : `xnl.lua` `bb39f2a`, `xcmp.lua` `3d09008`, tous deux du 17/07/2017) |
| Licence amont | GPL-2.0 (fichier `LICENSE` amont, GPLv2, copié ici) ; aucune mention « or later » en dehors du texte de la licence, d'où `GPL-2.0-only` ; les scripts n'ont pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur XCMP / XNL natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `xnl.lua` | Protocole `xnl`, TCP 8002, table `xnl.proto` |
| `xcmp.lua` | Protocole `xcmp`, sous-protocole 1 de XNL |
| `LICENSE` | Licence GPLv2 amont |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier les deux `.lua` dans le dossier `plugins` de Wireshark, recharger
les plugins Lua, puis filtrer avec `xnl` ou `xcmp`.

## Remarques

- **Ordre de chargement** : `xcmp.lua` appelle `Field.new("xnl.opcode")`
  et `Field.new("xnl.transaction")` dès son chargement, alors que Wireshark
  charge les scripts par ordre alphabétique (`xcmp` avant `xnl`). L'amont
  prévoit un contournement commenté : renommer `xnl.lua` en `xnl.luainc`
  et décommenter `dofile("xnl.luainc")` dans `xcmp.lua`. Sans cela, le
  chargement de `xcmp.lua` peut échouer (non vérifié).
- `dissect_address` et `dissect_xnl_payload` sont des fonctions globales.
- L'amont précise que le projet n'est ni produit ni approuvé par Motorola
  Solutions. Pas de capture d'exemple amont ; non vérifié dans Wireshark.
