# Growatt — wireshark-growatt (onduleurs solaires)

Dissecteur Wireshark Lua (partiel) du **protocole des enregistreurs Wi-Fi
Growatt**, échangé entre le module Wi-Fi d'un onduleur solaire Growatt et
le serveur `server.growatt.com` sur TCP 5279 : le contenu est désembrouillé
(XOR avec une clé) puis les paquets de ping, de données et de données en
tampon sont décodés (tensions, courants, puissances, énergie).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/akupila/wireshark-growatt |
| Commit importé | `75dc07a4eceeff8227ddddae1f69fca499fc0ef0` du 19/11/2024 (branche `main`, dernier commit) |
| Licence amont | MIT (`LICENSE` amont, © 2024 Antti Kupila ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Growatt natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `growatt.lua` | Dissecteur `growatt` (TCP 5279) |
| `captures/growatt.pcapng` | Capture d'exemple amont (`data/growatt.pcapng`) |

Fichier Lua importé tel quel ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête. La capture est une copie binaire
conforme.

## Utilisation

Copier `growatt.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, ouvrir
`captures/growatt.pcapng` et filtrer avec `growatt` (ou
`tcp.port == 5279 and tcp.len > 0`). Le README amont décrit la redirection
du trafic de l'enregistreur via une machine Linux (iptables DNAT / TEE).

## Remarques

- Lua 5.3 minimum (opérateur `~`), donc Wireshark 4.4 ou plus récent,
  selon l'amont.
- **Conflit de nom** : `dissectors/pygrowatt/` (issue #137) déclare aussi
  `Proto("growatt", …)` sur TCP 5279 ; ne charger qu'un des deux scripts à
  la fois.
- Rétro-ingénierie partielle, sans garantie selon l'auteur ; seuls les
  paquets ping et données / données en tampon sont décodés.
- Non repris : les captures d'écran et le `Makefile` d'installation amont.
- Non vérifié dans Wireshark, y compris sur la capture fournie.
