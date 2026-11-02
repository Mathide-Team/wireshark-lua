# libcsp — CubeSat Space Protocol sur Ethernet brut (simhau19)

Dissecteurs Wireshark Lua du CubeSat Space Protocol (CSP) version 2 de
[libcsp](https://github.com/libcsp/libcsp), protocole réseau des
nano-satellites CubeSat, tel qu'il circule sur l'interface Ethernet brute
de libcsp. Trois scripts coopèrent : `efp.lua` décode l'en-tête du
protocole de fragmentation Ethernet (EFP, EtherType `0x88B5`) et passe la
charge à `csp.lua`, qui décode l'en-tête CSP de 6 octets (priorité,
adresses et ports source et destination, drapeaux CRC, RDP, HMAC, FRAG)
et vérifie la CRC32C ; `rdp.lua` décode l'en-tête RDP (protocole fiable
de CSP) : drapeaux SYN, ACK, EAK, RST, numéros de séquence et d'acquit,
options de connexion et analyse des séquences (issue #782).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/simhau19/libcsp-dissector (`csp.lua`, `rdp.lua`, `efp.lua`) |
| Commit importé | `f0ed63ebf64f9972c0512d713a3a86adc739d5aa` du 09/04/2026 (dernier commit de la branche par défaut, « Create LICENSE ») ; dernière modification des trois scripts : commit `a523609778f7a82470bb351bcc9708a63e415c48` du 09/04/2026 (« initial commit ») |
| Licence amont | MIT (`LICENSE` amont, © 2026 Simen Haug) ; aucune mention dans les scripts. Le README amont indique que le travail part du dissecteur de [daniestevez/csp-tools](https://github.com/daniestevez/csp-tools) (`wireshark-dissector/csp-zmq.lua`), publié sous MIT ou Apache-2.0 au choix : la licence MIT retenue par l'auteur est cohérente. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur CSP ni EFP dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Les scripts sont repris tels quels (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête de chacun (convention du dépôt, issue #563).

Le dossier `csp-kantatamura` (issue #536) traite un autre transport du
même protocole (CSP 1 et 2 sur bus CAN) : les deux imports sont
distincts et se complètent.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/csp.lua` | Protocole `csp` (« Cubesat Space Protocol », ligne 26) ; champs `csp.*` (lignes 43 à 56, liste lignes 58 à 71) ; table CRC32C (ligne 91) et calcul (ligne 352) ; dissecteur ligne 363, appelé par `efp.lua` |
| `src/rdp.lua` | Protocole `csp.rdp` (« CSP Reliable Data Protocol », ligne 8) ; champs `rdp.*` (lignes 10 à 27) ; dissecteur ligne 63, appelé par `csp.lua` quand le drapeau RDP est levé |
| `src/efp.lua` | Protocole `efp` (ligne 10) ; EtherType `0x88B5` (lignes 6 et 51) ; dissecteur ligne 27 |

## Utilisation

Copier les trois fichiers de `src/` dans le dossier des plugins Lua
personnels (`~/.local/lib/wireshark/plugins/`). Wireshark les charge
dans l'ordre alphabétique, ce qui convient : `rdp.lua` utilise des
champs déclarés par `csp.lua`. Avec `-X lua_script:`, il faut charger
`csp.lua` avant `rdp.lua`. Les trames Ethernet d'EtherType `0x88B5` sont
décodées. Filtres : `efp`, `csp`, `csp.rdp`, `csp.destination`,
`csp.source_port`, `csp.crc.status`, `rdp.seq`, `rdp.flags.syn`…

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, scripts copiés dans le dossier des
plugins, puis chargés par `-X lua_script:`. Le dépôt amont ne contient
aucune capture. Essais sur une capture synthétique (Ethernet,
EtherType `0x88B5`, en-têtes CSP 2 et CRC32C calculées par un script à
part), non commitée :

| Essai | Résultat |
|---|---|
| CSP sans drapeau, « hello » | Info « 10:40 → 20:15  Len=5 », priorité « Normal (2) », données en hexadécimal |
| Drapeau CRC, CRC32C juste | « CRC32: 0x78863fcb », « CRC Status: Good (1) » |
| Drapeau CRC, CRC fausse | erreur experte « CRC mismatch: expected 0x78863FCB, got 0xDEADBEEF », « CRC Status: Bad (0) » ; filtre `csp.crc.status==0` : 1 paquet |
| EFP avec taille de segment < longueur du paquet | Info « Packet Fragment », charge confiée au dissecteur `data` |
| RDP : SYN avec options, SYN+ACK, données ACK (deux fois la même), EAK | en-tête RDP décodé (drapeaux, séquence, acquit), puis **erreur Lua** ligne 108 (« attempt to perform arithmetic on a nil value (local 'expected_seq') ») sur **chacun** des 5 paquets RDP : ni options SYN, ni analyse des séquences, ni colonne Info RDP |
| Chargement par `-X lua_script:` avec `rdp.lua` avant `csp.lua` | échec : « rdp.lua:55: bad argument #1 to 'new' (Field_new: a field with this name must exist) » |
| `efp.lua` seul | trames marquées EFP, en-tête EFP décodé, CSP non décodé |
| Filtres | `efp` : 9 paquets ; `csp` : 8 ; `csp.rdp` : 5 ; `rdp.seq==100` : 1 |

## Limites constatées

- `rdp.lua` compare les drapeaux booléens à `1` (`f_syn_flag_field()()
  == 1`, lignes 81, 100, 143, 146, 149, 152 et 166) alors que Wireshark
  renvoie `true` ou `false` : ces tests sont toujours faux. Le SYN n'est
  jamais reconnu, `rdp_expected_seq` reste vide et la ligne 108 lève une
  erreur Lua sur chaque paquet RDP. Les options SYN, les numéros EAK,
  l'analyse des retransmissions et la colonne Info RDP ne sont donc
  jamais produits.
- Réassemblage des fragments EFP non pris en charge (indiqué par
  l'amont) ; EtherType `0x88B5` (EtherType expérimental local de l'IEEE)
  fixe, sans préférence (ligne 6, « adjust if your firmware uses a
  different value »).
- Pas de prise en charge de HMAC, de CMP ni des autres interfaces de
  libcsp (UDP, ZeroMQ, CAN) ; la CRC32C est calculée sur les données
  seules.
- `efp.lua` ne vérifie pas la longueur des trames : une taille de
  segment supérieure aux octets présents lève une erreur Lua (ligne 38, « Range is out of bounds », constatée sur une trame à part).
- Les champs de `rdp.lua` sont nommés `rdp.*`, espace de noms du
  protocole natif RDP (Remote Desktop Protocol) ; `rdp.flags` existe
  déjà dans Wireshark. Les champs `csp.destination` et `csp.source_port`
  portent aussi les mêmes noms que ceux de `csp-kantatamura`.
- Les expertises de CRC et de séquence utilisent l'ancienne API
  `add_expert_info` (lignes 429 de `csp.lua` et 121 de `rdp.lua`).
