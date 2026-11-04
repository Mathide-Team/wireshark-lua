# SMP / MCUmgr (gestion d'appareils Zephyr sur UDP)

Dissecteur Wireshark Lua du **SMP (Simple Management Protocol) de MCUmgr**,
protocole de gestion à distance des objets connectés sous Zephyr RTOS
(et MCUboot) : mise à jour de firmware, redémarrage, statistiques,
paramètres, fichiers, shell… Il décode l'en-tête de 8 octets (opération
lecture/écriture requête/réponse v1 et v2, drapeaux, longueur, groupe,
numéro de séquence, commande, avec noms des groupes et commandes
standards), passe la charge CBOR au dissecteur CBOR natif de Wireshark, et
relie requêtes et réponses (champs `smp_mcumgr.response_in` /
`smp_mcumgr.request_in`). Transport UDP, port 1337 par défaut
(préférence).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/pdgendt/wireshark-smp-mcumgr (fichier `smp_mcumgr.lua`) |
| Commit importé | `2981ee6471a984198c7ade1ab32de75f6977c773` du 08/09/2026 (branche `main`, dernier commit ; dernière modification du dissecteur : `07f9ae9` du 08/09/2026) |
| Licence amont | MIT (`LICENSE` amont, © 2026 Pieter De Gendt) |
| Natif Wireshark 4.6.4 | Non — le `smp` natif (`packet-smp.c`) est le Session Multiplex Protocol de TDS, sans rapport ; pas de dissecteur MCUmgr natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `smp_mcumgr.lua` | Dissecteur `smp_mcumgr` (UDP 1337 configurable, « Décoder comme… ») |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `smp_mcumgr.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `smp_mcumgr`. Le port se change dans Préférences →
Protocoles → SMP_MCUMGR, ou via Analyse → Décoder comme… → UDP port.

## Remarques

- Couvre le transport UDP uniquement ; SMP sur Bluetooth LE (GATT), série
  ou CoAP n'est pas pris en charge par ce script.
- Le décodage de la charge dépend du dissecteur `cbor` natif (appel protégé
  par `pcall`, info experte en cas d'échec).
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
