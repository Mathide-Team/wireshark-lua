# cFS SBN — Software Bus Network de la NASA

Dissecteur Wireshark Lua des messages SBN (Software Bus Network), une
application du Core Flight System (cFS) de la NASA. Elle relie le bus
logiciel cFE de plusieurs processeurs ou instances cFS. Le dissecteur
lit l'en-tête (taille, type `NOMSG`, `SUB`, `UNSUB`, `APP`, `PROTO`,
identifiant de processeur) et les abonnements (version, nombre,
identifiants de message). La charge `APP` (paquet CCSDS) est passée
au dissecteur générique `data` (issue #525).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/nasa/SBN (`wireshark-sbn.lua`, à la racine) |
| Commit importé | `9cb933fc92e4caebb618f2c83b251b7cf07a9920` du 30/10/2026 (dernier commit de la branche par défaut `dev`) ; dernière modification du fichier : commit `9c32aea5283602c10a8288c21db0897824b8a8c0` du 07/01/2020 (Chris Knight) |
| Licence amont | Apache-2.0 : `LICENSE` du dépôt (aucun fichier `NOTICE`). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non pour SBN (le dissecteur natif `ccsds` décode les paquets CCSDS, mais pas l'enveloppe SBN) |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/wireshark-sbn.lua` | Protocole `cfs_sbn` (« Core Flight Software - Software Bus Networking ») sur UDP et TCP 2234 (lignes 14, 15, 92 et 93) ; champs `cfs_sbn.MsgSz`, `cfs_sbn.MsgType`, `cfs_sbn.CPUID`, `cfs_sbn.sub.Version`, `cfs_sbn.sub.Cnt`, `cfs_sbn.sub.MID` |

## Utilisation

Copier `src/wireshark-sbn.lua` dans le dossier des plugins Lua personnels
de Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis
Ctrl+Maj+L. Filtre : `cfs_sbn`. Autre port : modifier les lignes 14 et
15 ou `Decode As…`.

## Vérification à l'import

tshark 4.6.4 : le fichier se charge sans erreur (`luac5.4 -p` : OK).
Captures UDP synthétiques, construites d'après le code SBN de la même
époque que le script (commit `9c32aea`, `fsw/src/sbn_app.c`,
`SBN_PackMsg` : taille u16, type u8, processeur u32, gros-boutiste ;
`fsw/src/sbn_subs.c` : identité de 48 octets, nombre u16, puis par
abonnement MsgID u16 et QoS de 2 octets). Format actuel d'après
`dev` (`fsw/src/sbn_app.c`, lignes 102 à 105).

| Essai | Résultat |
|---|---|
| `SUB` (format 2020), 2 abonnements `0x0880` et `0x0881` | `MsgSz: 58`, `MsgType: SUB (1)`, `CPUID: 1`, `Version` lue ; **abonnements faux** : `0x0880`, puis `0x0000` (octets QoS) |
| `APP` (format 2020) avec un paquet CCSDS de 12 octets | en-tête exact ; charge affichée en `Data (12 bytes)` |
| `PROTO` sans charge | `MsgType: PROTO (4)`, `CPUID: 2` |
| `APP` au **format actuel** (taille u32, type, processeur, vaisseau u32) | décodage faux : `MsgSz: 0`, `MsgType: NOMSG (0)`, `CPUID: 201523200` |
| `SUB` tronqué à 30 octets | **erreur Lua** ligne 71 (`Range is out of bounds`) |

## Limites constatées

- **Format périmé** : depuis, SBN code la taille sur 32 bits et ajoute
  l'identifiant du vaisseau (en-tête de 13 octets au lieu de 7), et les
  MsgID sur 32 bits. Le trafic d'un SBN récent est mal décodé.
- Les 2 octets de QoS de chaque abonnement ne sont pas sautés (ligne
  81) : seul le premier identifiant est juste.
- `CPUID` lu à la position fixe 3 (ligne 67) ; champ `proto_sbn_sub`
  inexistant dans la liste des champs (ligne 47).
- Charge `APP` passée à `data` (ligne 87) plutôt qu'au dissecteur natif
  `ccsds` ; TCP sans réassemblage ni découpage de plusieurs messages
  par segment ; aucune vérification de longueur (erreur Lua sur paquet
  tronqué).
- Pas de capture réelle disponible.
