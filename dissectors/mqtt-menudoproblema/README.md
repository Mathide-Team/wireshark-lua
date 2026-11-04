# MQTT v3 (dissecteur Lua historique)

Dissecteur Wireshark Lua **historique** (2012) du protocole **MQTT v3**
(MQ Telemetry Transport) sur TCP 1883 : en-tête fixe (type de message,
DUP, QoS, RETAIN, longueur restante), puis CONNECT (nom du protocole,
version, drapeaux, keep-alive, identifiant client, will, identifiants),
PUBLISH, SUBSCRIBE / UNSUBSCRIBE et accusés de réception.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/menudoproblema/Wireshark-MQTT |
| Commit importé | `1e2f5486f19c147e87069f5892fd6aa31a3899f0` du 29/06/2014 (branche `master`, dernier commit) |
| Licence amont | LGPL-3.0-or-later (en-tête du fichier : « GNU Lesser General Public License […] either version 3 of the License, or (at your option) any later version », © 2012 Vicente Ruiz Rodríguez ; `LICENSE` amont : même avis) |
| Natif Wireshark 4.6.4 | **Oui** — dissecteur natif `mqtt` (v3.1, v3.1.1 et v5) ; ce script Lua est à considérer comme obsolète ou pédagogique |

Le `LICENSE` amont ne contient que l'avis de licence (pas le texte complet
de la LGPL v3, ni celui de la GPL v3 qu'elle complète) ; il est copié tel
quel. Texte officiel : https://www.gnu.org/licenses/lgpl-3.0.txt et
https://www.gnu.org/licenses/gpl-3.0.txt.

## Fichiers

| Fichier | Rôle |
|---|---|
| `mqtt.lua` | Dissecteur `MQTT` (TCP 1883) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier (l'avis de licence amont est
conservé).

## Utilisation

Copier `mqtt.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `mqtt`.

## Remarques

- **Concurrence avec le natif** : le script déclare `Proto("MQTT", …)`
  (même nom de filtre `mqtt` que le dissecteur natif) et s'enregistre sur
  TCP 1883. Le chargement peut échouer pour cause de nom déjà utilisé, ou
  remplacer le dissecteur natif sur ce port (non vérifié). Le dissecteur
  natif est bien plus complet (MQTT v5, TLS sur 8883, WebSocket).
- Le script appelle `require("bit")` (bibliothèque BitOp) ; sa présence
  comme module sous Wireshark 4.6 / Lua 5.4 n'est pas vérifiée.
- Pas de réassemblage TCP ni de capture d'exemple amont ; non vérifié dans
  Wireshark.
