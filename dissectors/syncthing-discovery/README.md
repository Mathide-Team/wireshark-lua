# Syncthing — annonces de découverte locale (v4)

Dissecteur Wireshark Lua des **annonces de découverte locale** de
[Syncthing](https://syncthing.net/) (Local Discovery Protocol v4,
https://docs.syncthing.net/specs/localdisco-v4.html) : vérification du
magique `0x2EA7D90B`, puis décodage du message Protobuf `Announce`
(identifiant de l'appareil, adresses, identifiant d'instance) par le
dissecteur **Protobuf** natif de Wireshark, à l'aide du schéma
`syncthing.proto` fourni. Port UDP 21027 (diffusion IPv4 / multidiffusion
IPv6).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/tmo1/wireshark-syncthing-dissector (fichiers `syncthing.lua` et `syncthing.proto`) |
| Commit importé | `746aed2826c10012af59e774251a5c14a5a0a006` du 27/02/2022 (branche `main`, dernier commit) |
| Licence amont | GPL-2.0-only (README : « licensed under the Gnu General Public License version 2 », sans « or later » ; texte `gpl-2.0.txt`, copié ici sous le nom `LICENSE`) ; auteur : Thomas More |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Syncthing natif (le décodage Protobuf est natif) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `syncthing.lua` | Protocole `syncthing` (« Syncthing Announcement »), UDP 21027 |
| `syncthing.proto` | Schéma Protobuf du message `syncthing.Announce` |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête du `.lua` (le `.proto` est copié sans
modification).

## Utilisation

1. Copier `syncthing.lua` dans le dossier `plugins` de Wireshark
   (ex. `~/.local/lib/wireshark/plugins/`).
2. Copier `syncthing.proto` dans un dossier et l'ajouter dans
   Préférences → Protocols → ProtoBuf → chemins de recherche.
3. Recharger les plugins Lua (Ctrl+Maj+L), puis filtrer avec `syncthing`.

## Remarques

- Seules les annonces de découverte locale sont décodées (pas le protocole
  d'échange de blocs BEP, chiffré en TLS, ni la découverte globale).
- L'identifiant d'appareil est affiché en octets bruts, pas au format
  Syncthing (base32 avec contrôle).
- Variables globales (`magic`, `length`…), comme dans l'amont. Pas de
  capture d'exemple amont ; non vérifié dans Wireshark.
