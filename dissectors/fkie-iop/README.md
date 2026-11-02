# IOP / JAUS — Fraunhofer FKIE

Dissecteur Wireshark Lua des messages **JAUS** (SAE AS5669 et AS5669A)
selon les profils d'interopérabilité **IOP** (robots terrestres), généré
par Fraunhofer FKIE à partir des définitions JSIDL : en-tête de transport
(version 1 AS5669 ou version 2 AS5669A, adresses
sous-système.nœud.composant, priorité, accusés, numéro de séquence)
et corps de 660 messages JAUS (services `urn.jaus.jss.core`, `mobility`,
`manipulator`, `ugv`, `environmentSensing`…) (issue #507).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/fkie/iop_wireshark_plugin (`fkie_iop.lua`, script déjà généré, à la racine du dépôt) |
| Commit importé | `6113ea4228d2a8f02f55669d8292582536576828` du 05/08/2026 (dernier commit de la branche par défaut `master`, et dernière modification de `fkie_iop.lua`) |
| Licence amont | MIT, « Copyright (c) 2014-2024 Fraunhofer FKIE » (`LICENSE` du dépôt), compatible avec la licence de ce dépôt (GPL-3.0-or-later) |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur JAUS/IOP dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563). Le générateur Python
amont (`fkie_iop_wireshark_plugin/`, schémas XSD, paquet ROS) n'est pas
importé.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/fkie_iop.lua` (≈ 26 700 lignes, 2,7 Mo) | Protocole `iop` sur UDP 3794 et 55555 et TCP 3794 (lignes 345 à 349) ; table `messagetable` des 660 dissecteurs de message, indexée par identifiant JAUS |

## Utilisation

Copier `src/fkie_iop.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis Ctrl+Maj+L.
Filtres : `iop`, `iop.message_id`, `iop.src.subsystem`, `iop.dst.node`,
`iop.v1.message_code`, `iop.flags.priority`… Chaque message a aussi son
propre protocole (par exemple `reportidentification_4b00`).

## Vérification à l'import

tshark 4.6.4 (Lua 5.4.8) : le fichier se charge sans erreur
(`luac5.4 -p` : OK) et ajoute 661 protocoles. Captures synthétiques
construites d'après la disposition décrite en tête du dissecteur
(lignes 136 à 160) :

| Essai | Résultat |
|---|---|
| AS5669 (v1), TCP 3794 : commande de transport `CONNECT` (0x0001) | `[CONNECT] 150.64.1->1.1.1, SeqNr: 1` |
| AS5669 (v1) : `QueryIdentification` (0x2B00) | en-tête complet décodé, corps `QueryType: 2 [Subsystem Identification]` |
| AS5669 (v1) : `SetTime` (0x0011) avec horodatage | **erreur Lua** ligne 1633 : `bad argument #3 to 'format' (number expected, got nil)` |
| AS5669A (v2), UDP 3794 : `QueryIdentification`, `ReportIdentification`, `RequestControl`, identifiant inconnu, paquets « first »/« middle » | **non décodé** : seuls la version et l'octet `message_type`/`hc_flags` s'affichent ; colonne Info laissée à UDP |

## Limites constatées

- **Incompatibilité avec Lua 5.4 (Wireshark 4.6)** : `bitVal` (ligne 120)
  assemble des restes de division devenus des nombres flottants
  (`"0.00.0"`) puis appelle `tonumber(…, 2)`, qui renvoie `nil`. Deux
  conséquences :
  - en AS5669A (version 2, cas courant des systèmes IOP), le test
    `hc_flag == 0` (ligne 267) échoue toujours : ni adresses, ni
    identifiant, ni corps de message ne sont décodés ;
  - les 95 dissecteurs de message qui utilisent `bitVal` (champs de bits :
    `SetTime`, `ReportTime`…) lèvent une erreur Lua dès que le champ est
    présent.
  Le script ne décode correctement qu'en AS5669 (version 1), pour les
  messages sans champ de bits. Correction non faite ici (import verbatim).
- Pour la même raison, les vecteurs de présence (`bitstr`, 223 messages)
  s'affichent sous la forme `0.00.00.0…` au lieu de `0000 0001`.
- En AS5669 (version 1), le corps transmis au dissecteur de message
  commence à l'octet 21 et doit répéter l'identifiant du message (lecture
  de `messageid` en tête de chaque dissecteur) ; à vérifier sur une
  capture réelle.
- Pas de réassemblage TCP ; la compression d'en-tête (`hc_flags` non nul)
  n'est pas traitée (branche vide).
- Environ 690 variables globales (`proto`, champs `pf_*`, `bitVal`,
  `bitAND`, `messageid`, `src_id`, `dst_id`, et un protocole global par
  message).
- Pas de capture réelle disponible ; captures synthétiques seulement.
