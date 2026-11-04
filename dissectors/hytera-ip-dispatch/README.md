# Hytera IP Dispatch — répéteurs DMR Hytera

Dissecteur Wireshark Lua (commentaires en allemand) des échanges UDP
entre le logiciel **Hytera IP Dispatch** et un répéteur DMR Hytera, issu
du projet radioamateur HytBridge de Lars Struß (DK7LST). Il définit sept
protocoles — `HyteraRRS` (Radio Registration Service), `HyteraLP`
(Location), `HyteraTP` (Telemetry), `HyteraTMP` (Text Message),
`HyteraRCP` (Radio Control), `HyteraSDM` (Self-Defined Message) et
`HyteraRTP` (audio) — qui partagent le même décodage d'en-tête :
signature `32 42 00`, type de paquet (Tx-Ctrl, ACK, keep-alive…),
compteur de séquence, et pour certains paquets type d'appel, identifiants
DMR source / destination et identifiant du répéteur. L'intervalle de
temps (TS1 / TS2) est déduit du port. Pour l'audio, les paquets sans
signature sont passés au dissecteur RTP natif.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/dk7lst/HytBridge (fichier `wireshark/HytIPDispatch.lua`) |
| Commit importé | `628c4a79c6c2d1f21c0a93140f6a753241cf6bc5` du 13/03/2022 (branche `master`, dernier commit ; dernière modification du script : `2f47c2c` du 11/04/2018) |
| Licence amont | GPL-3.0 (fichier `LICENSE` amont, GPLv3, copié ici ; README : « Open Source licensed under GPL v3 ») ; aucune mention « or later », d'où `GPL-3.0-only` ; le script n'a pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Hytera natif (RTP est natif) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `HytIPDispatch.lua` | Sept protocoles Hytera, ports UDP ci-dessous |
| `LICENSE` | Licence GPLv3 amont |

Ports UDP enregistrés (le premier de chaque paire serait TS1, le second
TS2, d'après le commentaire amont) : RRS 30001/30002, LP 30003/30004,
TP 30005/30006, TMP 30007/30008, RCP 30009/30010, SDM 3017/3018,
audio 30012/30014.

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le petit `install.bat` amont (copie dans
`%APPDATA%\Wireshark\plugins`) n'est pas repris.

## Utilisation

Copier `HytIPDispatch.lua` dans le dossier `plugins` de Wireshark,
recharger les plugins Lua (Ctrl+Maj+L), puis filtrer avec par exemple
`hyterarcp` ou `hyterartp`.

## Remarques

- **Lua 5.4** : la fonction `reverseID` utilise `bit32.bor`,
  `bit32.lshift` et `bit32.extract`. `bit32` n'existe plus en Lua 5.4 et
  la bibliothèque `bit` de Wireshark n'a pas d'`extract` : le décodage
  des paquets Tx-Ctrl de 18 octets et QSO-Data de 38 octets devrait donc
  échouer avec une erreur Lua sous Wireshark 4.6 (non vérifié). Les
  autres paquets ne sont pas concernés.
- Les ports SDM (3017/3018) diffèrent de la série 300xx des autres
  protocoles ; ils sont repris tels quels.
- Les protocoles, `HyteraDissector`, `UDP_Port`, `udp_table`… sont des
  variables globales. Le README amont qualifie le projet de « Under
  construction, not yet functional » et le destine à un usage
  éducatif / scientifique en radioamateur.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
