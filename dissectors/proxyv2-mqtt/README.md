# PROXY Protocol v2 + MQTT — courtiers MQTT derrière un répartiteur

Dissecteur Wireshark Lua des connexions **MQTT précédées d'un en-tête
PROXY Protocol v2**, situation courante quand les objets connectés
passent par un répartiteur de charge ou un proxy inverse qui termine TLS
avant le courtier MQTT : signature, version / commande, famille /
protocole, longueur, adresses IPv4 et ports d'origine et de destination,
extensions TLV (dont `PP2_TYPE_SSL` et le nom commun du certificat
client `PP2_SUBTYPE_SSL_CN`), puis transmission du reste du flux au
dissecteur MQTT natif. Les connexions MQTT sans en-tête PROXY sont aussi
acceptées. Port TCP 1884.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/dometec/proxyv2-mqtt-dissecort |
| Commit importé | `00ea760fd110d24296c98a358cc3a53bd6a3dd2a` du 02/03/2026 (branche `main`, dernier commit, qui est aussi la dernière modification de `proxyv2_mqtt.lua`) |
| Licence amont | MIT (`LICENSE` amont, © 2026 Domenico Briganti) |
| Natif Wireshark 4.6.4 | **En partie** — dissecteur natif `proxy` (`packet-proxy.c`, PROXY v1 et v2, heuristique TCP et UDP activée par défaut, IPv4 / IPv6 / TLV) ; ce script n'apporte que l'enchaînement direct vers MQTT sur le port 1884 |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `proxyv2_mqtt.lua` | Protocole `proxyv2_mqtt` sur TCP 1884, puis dissecteur `mqtt` natif |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

Copier `proxyv2_mqtt.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `proxyv2_mqtt` ou `mqtt`. Pour un autre port, modifier la
dernière ligne du script (README amont).

## Remarques

- Avant d'utiliser ce script, essayer le dissecteur natif `proxy`, qui
  reconnaît déjà PROXY v2 par heuristique et décode IPv6 et davantage de
  TLV.
- Seules les adresses IPv4 (famille `0x11`) sont décodées ; le script
  attend un segment de plus si l'en-tête PROXY est incomplet, puis passe
  la suite au dissecteur MQTT.
- Le champ `proxyv2.ssl.cn` révèle le nom commun du certificat client.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
