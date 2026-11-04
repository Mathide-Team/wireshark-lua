# OICQ amélioré — messagerie instantanée QQ (ancien protocole UDP)

Dissecteur Wireshark Lua de l'ancien protocole **OICQ** (QQ, messagerie
instantanée de Tencent) sur UDP 8000. Il vérifie les marqueurs de début
(`0x02`) et de fin (`0x03`), puis affiche drapeau, version, commande
(avec une liste d'environ 35 noms : connexion, messages, amis, groupes,
statut…), numéro de séquence, numéro QQ et bloc de données ; sinon il
passe la main au dissecteur `data`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/z-jack/wireshark-lua-plugins (fichier `oicq_enhanced.lua`) |
| Commit importé | `6b685ef6c4fb461997ac2b973b1ab665df1a8214` du 24/06/2018 (branche `master`, dernier commit) |
| Licence amont | MIT (fichier `LICENSE`, « Copyright (c) 2018 JackZ », copié ici) |
| Natif Wireshark 4.6.4 | Oui — dissecteur natif `oicq` sur UDP 8000 |

## Fichiers

| Fichier | Rôle |
|---|---|
| `oicq_enhanced.lua` | Protocole `qplus` (colonne « OICQ »), UDP 8000 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `oicq_enhanced.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `qplus`. Champs : `OICQ.Flag`, `OICQ.Command`, `OICQ.QID`…

## Remarques

- **Doublon du dissecteur natif `oicq`** : le script remplace celui-ci
  sur le port UDP 8000 (`DissectorTable:set`) ; son apport est la liste
  des noms de commandes. Les champs (`OICQ.*`, majuscules) sont distincts
  des champs natifs `oicq.*`.
- Protocole historique : le contenu des données (chiffré) n'est pas
  décodé.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
