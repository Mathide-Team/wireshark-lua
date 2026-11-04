# Chromium IPC Sniffer — dissecteurs IPC de Chrome / Chromium

Dissecteurs Wireshark Lua de l'outil **Chromium IPC Sniffer**, qui capture
sous Windows les échanges inter-processus de Chrome / Chromium passant par
des canaux nommés (*named pipes*) et les envoie à Wireshark :

- `npfs` : en-tête de capture de l'outil (processus source / destination,
  canal nommé…), transporté sous l'ethertype `0x0807` ;
- `mojo` (Mojo Core : ports, nœuds, invitations, poignées…) ;
- `ipcz` (successeur de Mojo Core : portails, routeurs, colis…) ;
- `mojouser` (appels de méthodes `.mojom` avec nom d'interface et de
  méthode, à partir des tables `helpers/`) ;
- `legacyipc` (ancien IPC de Chromium) ;
- `mojodata` (contrôle des *data pipes*) et `audiosync`
  (`\pipe\chrome.sync.*`).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/tomer8007/chromium-ipc-sniffer (dossier `Chrome IPC Sniffer/Dissectors/`) |
| Commit importé | `f72c80b4eec42c0fb8956f1a941420c6f8835038` du 10/12/2025 (branche `master`, dernier commit ; dernière modification du dossier `Dissectors/` : `9325dcd` du 10/12/2025) |
| Licence amont | GPL-3.0-only (fichier `LICENSE` GPL v3, copié ici ; pas de mention « or later ») ; `helpers/json.lua` : MIT (bibliothèque rxi/json.lua, © 2020 rxi, licence en tête du fichier) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Mojo / IPCZ / IPC Chromium natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `npfs.lua` | Protocole `npfs` (« NamedPipe Capture Protocol »), ethertype `0x0807`, aiguillage vers les autres |
| `mojo_core.lua`, `ipcz.lua`, `mojo_user.lua`, `legacy_ipc.lua`, `mojo_data_pipe.lua`, `audio_sync.lua` | Protocoles `mojo`, `ipcz`, `mojouser`, `legacyipc`, `mojodata`, `audiosync` |
| `helpers/common.lua` | Fonctions communes (types de processus Chrome, lecture de fichiers, chemin du script) |
| `helpers/json.lua` | Analyseur JSON rxi/json.lua (MIT) |
| `helpers/mojo_interfaces_map.lua` | Table générée identifiant de méthode → nom `.mojom` (pour un `chrome.dll` donné) |
| `helpers/mojo_interfaces.json` (3,4 Mo), `helpers/legacy_ipc_interfaces.json` | Descriptions générées des interfaces, lues au chargement |

Fichiers `.lua` importés tels quels ; seule une en-tête SPDX + provenance
de quatre lignes a été ajoutée en tête. Les fichiers JSON sont copiés sans
modification. Le programme de capture (C#, `chromeipc.exe`) n'est pas
importé.

## Utilisation

Ces dissecteurs n'ont de sens qu'avec le programme de capture amont
(`chromeipc.exe`, Windows), qui les copie lui-même dans le dossier
`plugins` de Wireshark, régénère les tables `helpers/` pour la version de
Chrome installée et alimente Wireshark par le canal `\\.\pipe\chromeipc`.
Pour une installation manuelle, copier tout le dossier (avec `helpers/`)
dans le dossier `plugins`, puis filtrer avec `npfs`, `mojo`, `ipcz` ou
`mojouser`.

## Remarques

- Prévu pour Windows : les `require("helpers\\common")` et les chemins
  `helpers\\*.json` utilisent des barres obliques inverses ;
  `helpers/common.lua` charge le module `json` par `require('json')`, ce
  qui suppose le dossier `helpers` dans `package.path`.
- Les tables `helpers/` correspondent à la version de Chrome de l'auteur
  (`chrome.dll` `b853b6f…`) : pour une autre version, les noms de méthodes
  peuvent être faux tant que l'outil ne les a pas régénérées.
- `legacy_ipc.lua` utilise `bit32.band` / `bit32.arshift` ; Wireshark 4.4
  et plus ne fournit plus `bit32` mais `bit` : ajouter `bit32 = bit` en
  tête du script si besoin.
- Les protocoles sont déclarés dans des variables globales, comme dans
  l'amont. Pas de capture d'exemple amont ; non vérifié dans Wireshark.
