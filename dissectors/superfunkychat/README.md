# SuperFunkyChat — messagerie d'exemple (TCP)

Dissecteur Wireshark Lua du protocole TCP de
[SuperFunkyChat](https://github.com/tyranid/SuperFunkyChat), application
de discussion d'exemple écrite par James Forshaw pour le livre
« Attacking Network Protocols ». Il gère le réassemblage TCP (message
coupé ou plusieurs messages par segment) et décode :

- l'en-tête : magique `BINX` éventuel (début de connexion), longueur,
  somme de contrôle, commande ;
- les commandes : demande / réponse de connexion (utilisateur, hôte),
  sortie, message, message direct (destinataire, expéditeur, texte),
  demande / réponse de liste des utilisateurs connectés.

Port TCP 12345 par défaut (préférence `port`, activable / désactivable).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/0x1452/SuperFunkyChat-Dissector (fichier `chat_dissector.lua`) |
| Commit importé | `65ae7ee8eaad120413926d8bd13ed1368272af9b` du 27/03/2021 (branche `main`, dernier commit) |
| Licence amont | Unlicense (fichier `LICENSE`, domaine public, copié ici) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur SuperFunkyChat natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `chat_dissector.lua` | Protocole `chat` (« SuperFunkyChat Protocol ») sur TCP 12345 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. La capture d'écran amont n'est pas importée.

## Utilisation

Copier `chat_dissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer
`wireshark -X lua_script:chat_dissector.lua`, puis filtrer avec `chat`.

## Remarques

- Nom de protocole générique `chat` : conflit possible avec un autre
  plugin du même nom (une autre version SuperFunkyChat est suivie dans
  l'issue #428, sans licence à ce jour).
- Le niveau de débogage par défaut (`LEVEL_1`) écrit des messages dans la
  console Lua ; la somme de contrôle est affichée mais non vérifiée.
- La fonction `read_string` est globale, comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
