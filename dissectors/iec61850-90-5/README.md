# IEC 61850-90-5 (R-GOOSE / R-SV) et RFC 1240

Dissecteurs Wireshark Lua pour le **routage des messages IEC 61850 sur IP**
défini par l'IEC TR 61850-90-5:2012 (transmission de synchrophaseurs selon
l'IEEE C37.118) : transport OSI sans connexion sur UDP (RFC 1240 / ITU
X.234, UDP 102), puis en-tête de session IEC 61850-90-5 (SPDU ID… jusqu'au
champ `Simulation`), avec délégation aux dissecteurs natifs `goose` ou `sv`
selon le type de charge utile. Seules les APDU **R-GOOSE** et **R-SV** sont
décodées (APDU « Tunnelled » et « MGMT » non prises en charge, selon
l'amont).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/josemariasaldana/IEC61850-90-5-Wireshark-LUA-Dissector |
| Commit importé | `d52288ab0eabb487f7f18d4099609e6886686264` du 04/03/2021 (branche `main`, dernier commit) |
| Licence amont | GPL-3.0-only (`LICENSE` amont : texte de la GPL v3, sans mention « or any later version » ; pas d'en-tête de licence dans les fichiers Lua) |
| Natif Wireshark 4.6.4 | Non selon l'issue (`tshark -G protocols`) ; les dissecteurs natifs `goose` et `sv` sont utilisés pour la charge utile |

Auteur amont : Jose Saldana (Fondation CIRCE), projet H2020 FARCROSS.

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `rfc1240.lua` | Dissecteur `RFC1240` (UDP 102) : en-tête de transport OSI sans connexion, appelle `iec61850_90_5` |
| `iec61850-90-5.lua` | Dissecteur `iec61850_90_5` : en-tête de session, puis appel de `goose` ou `sv` |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête de chaque fichier. Les captures d'écran
amont ne sont pas reprises.

## Utilisation

Copier les deux fichiers `.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `rfc1240` ou `iec61850_90_5` sur un trafic R-GOOSE / R-SV
(UDP 102).

## Remarques

- `rfc1240.lua` récupère `iec61850_90_5` avec `Dissector.get` au moment de
  la dissection : les deux fichiers doivent être chargés.
- L'enregistrement sur UDP 102 peut entrer en concurrence avec un
  traitement natif de ce port (non vérifié sur Wireshark 4.6.4).
- Pas de sécurité / signature 90-5 décodée ; pas de capture d'exemple amont.
- Non vérifié dans Wireshark.
