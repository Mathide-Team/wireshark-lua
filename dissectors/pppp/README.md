# PPPP (P2P des caméras IP grand public)

Dissecteur Wireshark Lua du **protocole P2P « PPPP »** (Peer-to-Peer
Protocol, souvent appelé CS2 / PPCS) utilisé par de nombreux objets
connectés, surtout des caméras IP chinoises bon marché : messages
d'initialisation, d'interrogation du serveur, de perforation NAT
(punch), de session, de données (DRW) et d'acquittement, sur UDP, avec
désobscurcissement du trafic « chiffré » par clé pré-partagée (PSK). Le
fichier `PPPP.md` documente le protocole et les PSK connues.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/magicus/pppp-dissector |
| Commit importé | `3ea9a7261f028fe2c75d141cb430bc29a162e2b0` du 05/05/2025 (branche `main`, dernier commit) |
| Licence amont | MIT (`LICENSE` amont et en-tête du fichier : « Copyright (C) 2023, Magnus Ihse Bursie », « Licensed under the MIT license ») |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur PPPP natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `pppp_dissect.lua` | Dissecteur `pppp` (heuristique UDP), préférence `pppp.psk` |
| `PPPP.md` | Description amont du protocole et table des PSK connues (en anglais) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête du fichier Lua (l'en-tête amont est
conservée).

## Utilisation

Copier `pppp_dissect.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `pppp`. Pour un trafic « chiffré » dont la PSK n'est pas
parmi les trois testées automatiquement : Préférences → Protocols → PPPP →
`Pre-shared Key` (voir la table de `PPPP.md`).

## Remarques

- **`bit32` absent des Wireshark récents** : le désobscurcissement par PSK
  appelle `bit32.band` / `bit32.bxor` (8 appels), absents de Lua 5.4
  (Wireshark 4.6 fournit `bit`) ; sans `bit32` global, le décodage du
  trafic chiffré échoue. Contournement local : `bit32 = bit` en tête du
  script (non fait, fichier conservé tel quel ; non vérifié).
- Heuristique UDP : peut coexister avec `dissectors/eufy-security/`
  (protocole Eufy dérivé de PPPP) ; ne charger que celui qui convient.
- Selon l'auteur, plus lent qu'un dissecteur en C ou WSGD.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
