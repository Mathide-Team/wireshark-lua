# ZAB — ZooKeeper (client ↔ serveur)

Dissecteur Wireshark Lua des messages échangés entre un client et un
serveur **Apache ZooKeeper** (l'amont l'appelle « ZAB 1.0 ») : connexion
et réponse (version, zxid, délai, session, mot de passe, lecture seule),
requêtes et réponses par code d'opération (`CREATE`, `DELETE`, `EXISTS`,
`GETDATA`, `SETDATA`, `GETACL`, `SETACL`, `GETCHILDREN`/`GETCHILDREN2`,
`SYNC`, `PING`, `CHECK`, `MULTI`, `CREATE2`, `RECONFIG`…) avec les structures `Stat`,
ACL, chemins et données, événements de surveillance (`WATCH EVENT`),
`SETWATCHES`, `AUTH`, et commandes « quatre lettres » (`ruok`, `stat`,
`mntr`…). Les échanges internes entre serveurs (le protocole ZAB
proprement dit) ne sont pas pris en charge (issue #448).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ceache/zab_dissector (`zab.lua`) |
| Commit importé | `e949a7fe14e95982462c2b7434b75b0579d2a324` du 20/08/2026 (dernier commit de la branche par défaut `master`) ; dernière modification de `zab.lua` : commit `55b8f51de964ef5eaf4525b9adf23ef37109e65a` du 20/08/2026 |
| Licence amont | MIT, « Copyright (c) 2020 Charles-Henri de Boysson » (`LICENSE` du dépôt), compatible avec la licence de ce dépôt (GPL-3.0-or-later) |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur ZooKeeper (`tshark -G protocols` ne donne que `zabbix`) |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563). Les captures de test
amont (`tests/fixtures/<opération>/instance_<n>.pcapng`) et leurs sorties
de référence (`.txt`) sont copiées telles quelles dans `captures/`, sous
le nom `<opération>_<n>`. Les scripts de test Nix et Python amont ne sont
pas importés.

Autre copie connue : `zookeeper/zookeeper_dissector.lua` du dépôt
hezhangjian (voir `dissectors/pulsar-hezhangjian/README.md`), copie de
ce script restée dans ce dépôt-là et non importée.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/zab.lua` | Protocole `zab` (« ZAB 1.0 ») sur TCP 2181 (préférence « Port number », `Decode As…` possible) ; réassemblage TCP et plusieurs messages par segment ; suivi des `xid` par client pour apparier les réponses aux requêtes |
| `captures/*.pcapng` | 19 captures amont : `connect`, `create` (4), `delete` (2), `exists` (3), `get_data` (4), `multi` (2), `ping`, `reconfig`, `set_data` |
| `captures/*.txt` | Champs `zab.*` attendus par paquet ZAB (référence amont) |

## Utilisation

Copier `src/zab.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis Ctrl+Maj+L.
Port par défaut 2181 ; autre port : préférence du protocole, `Decode As…`,
ou en ligne de commande :

```sh
tshark -X lua_script:zab.lua -X lua_script1:ports=2181,2182,20000 -r capture.pcapng -Y zab
```

Filtres : `zab`, `zab.opcode`, `zab.xid`, `zab.err`, `zab.path`,
`zab.zxid`, `zab.session`…

## Vérification à l'import

Avec tshark 4.6.4, le fichier se charge sans erreur (`luac5.4 -p` : OK).

| Essai | Résultat |
|---|---|
| 19 captures amont, champs `zab.*` comparés aux `.txt` de référence | 18 identiques ; `multi_2` : la trame 3 contient deux messages, que la référence amont regroupe (un seul `zab.xid`) alors que tshark liste les champs des deux. Ce n'est pas une erreur de décodage |
| Synthétique : `GETDATA` coupé en deux segments TCP (10 + 107 octets) | réassemblé (« 2 Reassembled TCP Segments ») ; chemin et réponse (`Error: Success (0)`) décodés |
| Synthétique : `ruok` / `imok` | `4LW ruok request` / `4LW reply` |
| Synthétique sur TCP 20000 | rien sans option ; décodé avec `-X lua_script1:ports=2181,20000` |
| `exists_3` (trame 3, client dont la connexion n'est pas dans la capture) | seuls `zab.length` et `zab.xid` sont décodés (comme dans la référence amont) ; le reste de la trame est pris par l'heuristique SMPP (`Replace_sm`, « Malformed Packet ») |

## Limites constatées

- Le sens (requête ou réponse) dépend du message `CONNECT` vu en début de
  connexion (table `CLIENTS`, ligne 173 de `src/zab.lua`, 168 en amont) :
  une capture qui commence en cours de session n'est décodée que
  partiellement, et le reste de la trame peut être attribué à un autre
  dissecteur heuristique (cas `exists_3`).
- La colonne Info n'est renseignée que pour `CONNECT`, `AUTH`,
  `SETWATCHES`, `WATCH EVENT` et les commandes « quatre lettres » ; les
  autres opérations gardent l'Info TCP.
- Données de longueur nulle affichées `Data: <MISSING>`.
- SASL non pris en charge (TODO amont) ; échanges entre serveurs
  (élection, réplication) non pris en charge.
- Variable globale `ZabProto` (ligne 2137, 2132 en amont).
- Captures amont produites en conteneur (adresses 172.18.0.x) par la suite
  de tests kazoo, pas sur un ensemble ZooKeeper de production.
