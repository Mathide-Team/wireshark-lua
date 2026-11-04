# Z-Wave Serial API (échanges hôte ↔ puce Z-Wave)

Dissecteur Wireshark Lua de l'**API série Z-Wave**, protocole entre une
puce / clé USB Z-Wave (contrôleur domotique) et le logiciel hôte : trames
SOF (données) et trames auxiliaires ACK / NAK / CAN, drapeau
requête / réponse, identifiant de commande, somme de contrôle. Les données
sont ensuite réparties, selon le sens (hôte → puce ou puce → hôte) et le
type (requête / réponse), vers des sous-dissecteurs par commande
(`ZW_SendData`, `ZW_GetVersion`, liste des nœuds, informations de
protocole et de routage, capacités du contrôleur et de l'interface série,
temporisations…) et, pour `ZW_SendData` / `ApplicationCommandHandler`, vers
des classes de commandes applicatives (No Operation, Multilevel Switch).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/dottedmag/wireshark-zwave |
| Commit importé | `557c8578df4d6e70233ab39fd5d01ef39903f7e8` du 31/10/2020 (branche `master`, dernier commit) |
| Licence amont | GPL-3.0-only (README amont : « (c) 2020 Misha Gusarov — All code in this repository is licensed under GNU GPL v3. See `COPYING` file. », sans « or later » ; `COPYING` amont : texte de la GPL v3) |
| Natif Wireshark 4.6.4 | Non — Wireshark connaît le type de lien `WTAP_ENCAP_ZWAVE_SERIAL` (211, LINKTYPE 287), mais n'a pas de dissecteur Z-Wave natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme du `COPYING` amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `zwave.lua` | Dissecteur `zwave_serial` (encapsulation 211 = Z-Wave série) ; crée les tables `zwave.host_request`, `zwave.host_response`, `zwave.chip_request`, `zwave.chip_response` |
| `zwave-send-data.lua` | `ZW_SendData` (requête, réponse, rappel) et `ApplicationCommandHandler` ; crée les tables `zwave.command_request` / `zwave.command_response` |
| `zwave-app-noop.lua`, `zwave-app-switch-multilevel.lua` | Classes de commandes No Operation et Multilevel Switch |
| `zwave-application-node-information.lua`, `zwave-get-controller-capabilities.lua`, `zwave-get-node-protocol-info.lua`, `zwave-get-random-word.lua`, `zwave-get-routing-info.lua`, `zwave-get-suc-node-id.lua`, `zwave-memory-get-id.lua`, `zwave-node-list.lua`, `zwave-request-node-info.lua`, `zwave-serial-get-capabilities.lua`, `zwave-set-timeouts.lua`, `zwave-version.lua` | Une commande de l'API série par fichier |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête de chaque fichier. Les sous-dissecteurs
s'enregistrent dans leur fonction `init()`, donc l'ordre de chargement des
fichiers n'a pas d'importance.

## Utilisation

Copier tout le dossier dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/zwave-serial-api/`), recharger les
plugins Lua, puis ouvrir une capture pcap de type de lien Z-Wave série
(LINKTYPE 287) et filtrer avec `zwave_serial`.

## Remarques

- **Complémentaire de `dissectors/zwave-zniffer/`** (#189) : ce dernier
  décode les trames radio (Zniffer), celui-ci l'API série du contrôleur ;
  les noms de protocoles ne se chevauchent pas.
- Travail en cours selon l'auteur : seules certaines commandes sont
  décodées, et la structure des paquets est « glanée » dans diverses
  implémentations (« à prendre avec précaution », README amont) ; la somme
  de contrôle n'est pas vérifiée (FIXME amont).
- Utilise la bibliothèque `bit` (fournie par Wireshark), pas `bit32`.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
