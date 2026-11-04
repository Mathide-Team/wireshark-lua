# IEC 61850 GOOSE / SV / MMS (dissecteur Lua simplifié)

Dissecteur Wireshark Lua **basique** des trois profils de communication
IEC 61850 des postes électriques : **GOOSE** (EtherType `0x88B8`),
**Sampled Values** (EtherType `0x88BA`) et **MMS** (TCP 102, 1002, 10002 ;
UDP 102), sous un protocole unique `IEC61850` (type d'APDU, longueur,
identifiant d'invocation, service MMS, décodage BER simplifié).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Marnm/iec61850-packets-dec-lua |
| Commit importé | `0969d65fdc4cefa8670e3cbcc3e669f46777a330` du 27/08/2026 (branche `main`, dernier commit) |
| Licence amont | Apache-2.0 (`LICENSE` amont ; pas d'en-tête de licence dans le fichier Lua ; pas de fichier `NOTICE` amont) |
| Natif Wireshark 4.6.4 | **Oui** — dissecteurs natifs complets `goose`, `sv` et `mms` (via `tpkt`/`cotp`) ; ce script Lua est à considérer comme obsolète ou pédagogique |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `iec61850_dissector.lua` | Dissecteur `IEC61850` (champs `iec61850.*`) |
| `README_IEC61850_PLUGIN.md` | Documentation amont (en chinois) : installation, fonctions, filtres |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête du fichier Lua.

## Utilisation

Copier `iec61850_dissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `iec61850`.

## Remarques

- **Remplace les dissecteurs natifs** : le script prend les EtherType
  `0x88B8` / `0x88BA` et les ports TCP 102 / UDP 102 à la place de `goose`,
  `sv` et `tpkt` (donc `cotp`/`mms`), dont le décodage est bien plus
  complet. Ne le charger que pour un usage ciblé, puis le retirer.
- **`bit32` absent des Wireshark récents** : le décodage BER appelle
  `bit32.band` (2 appels), absent de Lua 5.4 (Wireshark 4.6 fournit
  `bit`) ; contournement local : `bit32 = bit` en tête du script (non fait,
  fichier conservé tel quel ; non vérifié).
- Les métadonnées `set_plugin_info` (auteur « IEC 61850 Working Group »,
  dépôt `github.com/iec61850/wireshark-plugin`) ne correspondent pas au
  dépôt amont réel ; la provenance retenue est celle du tableau ci-dessus.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
