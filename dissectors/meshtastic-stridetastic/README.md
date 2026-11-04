# Meshtastic — captures PCAP-NG de STRIDEtastic

Dissecteur Wireshark Lua fourni avec STRIDEtastic, cadre de
supervision des réseaux maillés radio LoRa Meshtastic. STRIDEtastic
enregistre le trafic qu'il reçoit (MQTT, radio série ou TCP) dans des
fichiers PCAP-NG : chaque trame contient un message protobuf Meshtastic
brut, et son type est donné par un commentaire de trame
(`type=meshtastic.MeshPacket`, `type=meshtastic.Data`…). Le script lit
ce commentaire et confie la trame au dissecteur protobuf de Wireshark
avec le bon type de message. Il décode ensuite la charge utile de
`Data` selon le `portnum` (texte, position, télémétrie, routage…),
affiche les adresses `!xxxxxxxx` dans les colonnes Source et
Destination et ajoute les noms des nœuds (issue #832).

Ce dossier est distinct de `dissectors/meshtastic-talk/` : autre
auteur et autre approche (captures PCAP-NG de STRIDEtastic sur
DLT_USER15, guidées par les commentaires de trame).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/0wulf/stridetastic (`wireshark/meshtastic.lua`) |
| Commit importé | `1e699d8f1a22007ef14e0f9ce48386570bafc04f` du 14/05/2026 (dernier commit de la branche par défaut `main`) ; dernière modification du fichier : commit `b84cc537deebe1e2235cbe3cac573873c34da747` du 13/12/2025 |
| Licence amont | GPL-3.0-only : `LICENSE` du dépôt (texte de la GPLv3, sans mention « or later » dans le dépôt) ; le script n'a pas d'en-tête de licence. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur Meshtastic dans `tshark -G protocols` |

Texte de la licence : fichier `LICENSE` de ce dossier (copie conforme
du `LICENSE` amont). Le fichier est repris tel quel (aucune
modification) ; seule l'en-tête de provenance de cinq lignes est ajoutée
en tête de `meshtastic.lua` (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/meshtastic.lua` | Recherche du dissecteur protobuf (ligne 39, erreur au chargement s'il manque) ; lecture du commentaire de trame (ligne 49) ; sous-protocoles par type de message (ligne 63) ; table des `portnum` (lignes 131 à 151) ; décodage de `meshtastic.Data.payload` (lignes 153 et 175) ; colonnes et noms des nœuds (ligne 183) ; aiguillage par type (ligne 227) ; protocole `meshtastic` (« Meshtastic Capture », ligne 292) ; post-dissecteur « Meshtastic Node Labels » (ligne 347) ; inscription ligne 356 |

## Utilisation

1. Copier `src/meshtastic.lua` dans le dossier des plugins Lua
   personnels (`~/.local/lib/wireshark/plugins/`).
2. Indiquer à Wireshark les fichiers `.proto` de Meshtastic (dépôt
   https://github.com/meshtastic/protobufs) : Préférences → Protocols →
   Protobuf → Protobuf search paths, en ajoutant la racine du dépôt
   cloné. Sans eux, seuls les messages texte sont lisibles.
3. Associer le DLT 162 au protocole : Préférences → Protocols →
   DLT_USER → Encapsulations Table, entrée « User 15 (DLT=162) », charge
   utile `meshtastic` (voir les limites : sans cette étape, rien n'est
   décodé).

Filtres : `meshtastic`, `meshtastic.text`, `meshtastic.src_long_name`,
`meshtastic.dst_long_name`, `meshtastic.src_mac`, et les champs
protobuf (`protobuf.field.name == "long_name"`…).

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : chargement sans erreur. Le
dépôt amont ne contient aucune capture. Essais sur une capture produite
par l'enregistreur amont lui-même
(`api_stridetastic/stridetastic_api/utils/pcap_writer.py`, même commit)
avec des messages protobuf codés à la main ; capture non commitée.
Fichiers `.proto` : dépôt meshtastic/protobufs (paquet `meshtastic`).

| Essai | Résultat |
|---|---|
| Capture lue sans réglage | Aucun décodage : « Packet 37 », trame vue comme USER 15 (encapsulation 60) |
| Avec l'entrée DLT_USER, sans fichiers `.proto` | Sous-protocoles appliqués (`Meshtastic_MeshPacket`, `Meshtastic_Data`…) ; seul le message texte est lisible : « Bonjour Haguenau » |
| Avec DLT_USER et fichiers `.proto` : MeshPacket texte, de !11223344 à !FFFFFFFF | Colonnes « !11223344 → !FFFFFFFF », Info « Bonjour Haguenau id=3735928559 », Destinataire « Broadcast » |
| `Data` seul, `portnum` 1 | « Bonjour Haguenau » (sous-protocole TextMessage) |
| `meshtastic.protobuf.User` (nom du paquet Python) | « long_name=Station Test short_name=ST » |
| `meshtastic.protobuf.Position` | « latitude_i=487000000 longitude_i=78000000 » |
| MeshPacket NODEINFO_APP (`portnum` 4) portant un `User` | Charge utile lue comme `meshtastic.NodeInfo` : « num=9 user position », champs faux |
| Filtre `meshtastic.text` | Trames 1, 2, 3 et 8 |

## Limites constatées

- L'inscription `DissectorTable.get("wtap_encap"):add(162, …)`
  (ligne 356) utilise le numéro de DLT, alors que la table `wtap_encap`
  attend un numéro d'encapsulation Wireshark : le DLT 162 correspond à
  l'encapsulation 60 (USER 15). Les captures de STRIDEtastic ne sont
  donc pas décodées sans l'entrée DLT_USER décrite plus haut.
- Le `portnum` 4 (NODEINFO_APP) est décodé comme `meshtastic.NodeInfo`
  (ligne 133), alors que Meshtastic y transporte un `User` : les champs
  affichés sont faux, et le nom long du nœud n'est pas relevé.
- Les noms des nœuds ne sont relevés que dans les trames MeshPacket
  (ligne 183) ; une trame `User` seule ne remplit pas la table. Si le
  MeshPacket n'a pas de champ `from`, la clé est tirée du champ `id`,
  qui est l'identifiant du paquet (entier) et non celui du nœud
  (ligne 210). Dans nos essais, le champ « Sender » n'est jamais apparu.
- Le protocole s'appelle `meshtastic` (ligne 292), comme celui de
  `dissectors/meshtastic-talk/` : les deux scripts ne peuvent pas être
  chargés ensemble (« there cannot be two protocols with the same
  name »).
- Les fichiers `.proto` de Meshtastic ne sont pas fournis ; ceux qui
  importent `google/protobuf/descriptor.proto` (`nanopb.proto`,
  `field_metadata.proto`) provoquent un message d'erreur au chargement,
  sans effet sur le décodage.
- Le script exige le dissecteur protobuf de Wireshark et s'arrête au
  chargement s'il manque (lignes 39 à 42).
