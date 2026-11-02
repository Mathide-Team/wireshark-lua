# Crazyflie CRTP — protocole des nano-drones Crazyflie (evoggy)

Dissecteur Wireshark Lua du protocole CRTP (Crazy RealTime Protocol) des
nano-drones Crazyflie de Bitcraze. Il décode l'en-tête de capture ajouté
par l'extcap du même dépôt (type de liaison radio, USB ou UDP du
simulateur, sens, adresse radio, canal, numéro de série), puis l'octet
d'en-tête CRTP (port, canal, compteurs SafeLink) et la charge utile des
ports console, paramètres, commande, mémoire, journalisation,
localisation, consignes génériques et haut niveau, plateforme et
contrôle de liaison (issue #778).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/evoggy/wireshark-crazyflie (`dissector/crtp-dissector.lua`) |
| Commit importé | `c707ffa390ad77e69e8525ffc5fa804e4f29dd4b` du 21/10/2026 (dernier commit de la branche par défaut, seul commit du dépôt, auteur Marcus Eliasson) |
| Licence amont | MIT OR Apache-2.0, au choix : section « License » du `README.md` amont (ligne 89 : « MIT OR Apache-2.0 ») et champ `license` du `Cargo.toml` amont. Le dépôt ne contient **aucun fichier de licence** et le script aucune mention. Les deux licences sont compatibles avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non. Le filtre natif `crtp` de Wireshark désigne un autre protocole homonyme (« CRTP », variantes CNTCP, CS, CUDP 8 et 16), sans rapport avec Crazyflie ; aucun dissecteur Crazyflie dans `tshark -G protocols` |

Aucun texte de licence n'est fourni par l'amont : il n'en est pas
inventé ici (pas de fichier `LICENSE` dans ce dossier, le validateur
l'accepte avec un avertissement). L'identifiant SPDX
`MIT OR Apache-2.0` reprend exactement la déclaration de l'auteur. Le
script est repris tel quel (aucune modification de code) ; seule
l'en-tête de provenance de cinq lignes est ajoutée en tête (convention
du dépôt, issue #563). L'extcap en Rust (`src/main.rs`, `Cargo.toml`)
n'est pas importé : ce dépôt ne regroupe que des dissecteurs Lua.

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/crtp-dissector.lua` | Protocole `crazyrealtimetprotocol` (« Crazy Real Time Protocol », ligne 7) ; champs `crtp.*` (lignes 10 à 113, liste ligne 116) ; types de liaison (ligne 213) et ports CRTP (ligne 227) ; décodeurs par port (lignes 352 à 1252) ; dissecteur ligne 1253 ; inscription sur `wtap_encap` `USER15` (DLT 162, lignes 1362 et 1363) |

## Utilisation

Copier `src/crtp-dissector.lua` dans le dossier des plugins Lua
personnels (`~/.local/lib/wireshark/plugins/`). Le script décode les
captures de type de lien `USER15` (DLT 162) produites par l'extcap
amont `crazyflie-extcap`, alimenté par une application
`crazyflie-link` compilée avec la fonctionnalité `packet_capture`.
Filtres : `crazyrealtimetprotocol`, ou les champs `crtp.port`,
`crtp.console_text`, `crtp.commander_thrust`, etc.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : chargement sans erreur. Le
dépôt amont ne contient aucune capture. Essais sur des captures
synthétiques `USER15` construites selon le format écrit par l'extcap
(`src/main.rs`), non commitées :

| Essai | Résultat |
|---|---|
| Radio, réception, port 0 (console) « Hello console\n » | colonnes `E7:E7:E7:E7:E7 (80) → Radio CF2-TEST`, Info « Console », `crtp.console_text` = « Hello console\n » |
| Radio, émission, port 3 (commande) roll 1,5, pitch −2, lacet 10, poussée 30000 | Roll 1.5 (deg), Pitch -2 (deg), Yaw Rate 10 (deg/s), Thrust 30000 ; filtre `crtp.port == 3` : 1 paquet |
| USB, port 2 (paramètres), canal 0 | Info « Parameters », canal « Table Of Contents », octet restant en `Undecoded: 03` |
| Radio, port 5 (journalisation), canal 0 | Info « Logging », `Undecoded: 010203` |
| UDP (simulateur), console « SIM ok\n » | colonnes `127.0.0.1:19950 → UDP`, texte décodé |
| Type de liaison inconnu (9) | colonne Protocole « CRTP », Info vide, aucun arbre : abandon silencieux |
| Filtres | `crazyrealtimetprotocol` : 4 paquets sur 5 ; `crtp` : 0 (filtre du protocole natif homonyme) |

## Limites constatées

- Nom du protocole : `CrazyRealTimeTProtocol` (ligne 7, avec un « T »
  en trop), d'où le filtre `crazyrealtimetprotocol`, alors que les champs
  sont nommés `crtp.*`, espace de noms du protocole natif homonyme de
  Wireshark : `crtp` seul ne sélectionne pas ces paquets.
- Lié à `USER15` (DLT 162), type de lien réservé à l'usage privé :
  conflit possible avec d'autres scripts qui l'utilisent ; aucune
  préférence pour le changer.
- Le texte de console est affiché avec les échappements (`\n`).
- Pour un type de liaison inconnu, le dissecteur renvoie sans rien
  ajouter (ligne 1263) mais a déjà écrit « CRTP » dans la colonne
  Protocole.
- Nombreuses variables globales : `crtp`, `link`, `crtp_start`,
  `undecoded`, `port_name`, `channel_name`, `wtap_encap`, `type`,
  `num_type`… et toutes les fonctions `handle_*`, `format_*` et
  `get_crtp_port_channel_names` ; conflits possibles avec d'autres
  scripts.
- Utilise la bibliothèque `bit` (`bit.band`, `bit.rshift`), encore
  fournie par Wireshark 4.6.
