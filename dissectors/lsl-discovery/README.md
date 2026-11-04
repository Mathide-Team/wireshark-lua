# LSL — découverte des flux Lab Streaming Layer

Dissecteur Wireshark Lua des paquets UDP de **découverte de flux** de
[Lab Streaming Layer](https://github.com/sccn/liblsl) (LSL : acquisition
synchronisée de signaux EEG, de capteurs, etc.) : requête
`LSL:shortinfo` (multidiffusion ou diffusion vers UDP 16571) avec la
requête de sélection, le port de réponse et l'identifiant de requête, et
réponse `shortinfo` (identifiant de requête et description XML du flux).
Les échanges de données des flux (TCP) ne sont pas décodés (issue #514).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/sccn/liblsl (`testing/lsl.lua`, dissecteur fourni avec la bibliothèque) |
| Commit importé | `992635a9277bb7cc71b6516e7608182e5e2976f3` du 14/10/2026 (dernier commit de la branche par défaut `dev`) ; dernière modification de `lsl.lua` : commit `b5fe3c7089ff16e64f83dbfeb9feabf0c325b955` du 13/10/2021 (Tristan Stenner) |
| Licence amont | MIT : `LICENSE` du dépôt (« Copyright (C) 2012 Christian A. Kothe »), suivi de la liste des bibliothèques tierces de liblsl. GitHub l'affiche « NOASSERTION » à cause de cette liste ajoutée. Le fichier porte la mention « (C) 2020 Tristan Stenner » sans licence propre : c'est la licence du dépôt qui s'applique. Compatible avec la licence de ce dépôt (GPL-3.0-or-later) |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur LSL dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/lsl.lua` | Protocole `lsldiscovery` (« Labstreaminglayer Discovery ») sur UDP 16571 (ligne 61) ; champs `lsl.cmd`, `lsl.content`, `lsl.answerport`, `lsl.query`, `lsl.streaminfo` |

## Utilisation

Copier `src/lsl.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis Ctrl+Maj+L.
Filtre : `lsldiscovery`. Autre port : `Decode As…`.

## Vérification à l'import

tshark 4.6.4 : le fichier se charge sans erreur (`luac5.4 -p` : OK).
Captures synthétiques construites au format produit par liblsl
(`src/resolve_attempt_udp.cpp`, lignes 50 à 52 ; `src/udp_server.cpp`,
ligne 140, au commit importé) :

| Essai | Résultat |
|---|---|
| Requête `LSL:shortinfo\r\ntype='EEG' and name='BioSemi'\r\n16572 1234567890\r\n` | `Command: LSL:shortinfo`, `Content: type='EEG' and name='BioSemi'`, `Answer port: 16572`, `QueryID: 1234567890\r\n` |
| Requête courte `…\r\nname='EEG'\r\n16572 1234567890\r\n` | **erreur Lua** ligne 44 (`attempt to perform arithmetic on a nil value (local 'wspos')`) ; `Content` englobe la requête, le port et l'identifiant |
| Réponse `1234567890\r\n<?xml version="1.0"?><info>…</info>` depuis UDP 16571 | `QueryID: 1234567890` ; **`Streaminfo` amputé** des 12 premiers caractères (`n="1.0"?><info>…`) |
| Requête tronquée (sans second `\r\n`), commande autre que `LSL:` | `Command` seul ; laissée sans arbre |

## Limites constatées

- **Requêtes de moins de 14 caractères mal découpées.** Ligne 38, la
  recherche du deuxième `\r\n` reprend à la position `newlinepos+1`
  calculée sur le tampon précédent. Pour une requête courte, elle saute le
  vrai séparateur et finit par une erreur Lua. Les requêtes vides ou
  simples (`name='EEG'`) sont pourtant courantes.
- **Début du XML perdu dans la réponse** : ligne 58, le tampon déjà avancé
  est avancé une seconde fois (`buffer(newlinepos+1)`).
- `QueryID` de la requête garde le `\r\n` final ; colonnes Protocole et
  Info laissées à UDP.
- Seul le port 16571 est enregistré, et une réponse n'est reconnue que si
  son port source est 16571. Une réponse émise depuis un autre port (par
  exemple par un serveur UDP unicast de liblsl) n'est pas décodée.
- Pas de capture réelle disponible ; données des flux (TCP 16572 et
  suivants) non prises en charge.
