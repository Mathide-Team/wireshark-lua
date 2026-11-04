# ZPR ZDP — protocole de données de ZPR (Zero-trust Packet Routing)

Dissecteurs Wireshark Lua du **protocole ZDP du projet ZPR**
(https://zpr.org, routage de paquets « zero trust ») — à ne pas confondre
avec le Zigbee Device Profile (`zbee_zdp`), malgré l'intitulé de l'issue :
en-tête ZDP (type, ZPI, identifiant de flux, numéro de séquence, MAC
A2A, SAID, bourrage, HMAC), paquets de transit (en-tête IP de l'agent —
version, classe de trafic, étiquette de flux, limite de sauts, fragments
—, puis passage au dissecteur `ip` natif), et paquets de gestion
(inaccessibilité, MTU, demandes / réponses d'identifiant de flux, liaison
d'adresses d'acteur, ARP ZPR, gestion de clés, écho, rapports, hello,
configuration, attribution / révocation d'adresses ZPR, authentification,
acquittement). Un second script décode l'octet de sens (entrant /
sortant) d'un lien point à point.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/org-zpr/zpr-common (dossier `tools/`) |
| Commit importé | `59c225a5a6e87be2f5253ae82c111d28078fda72` du 05/10/2026 (branche `main`, dernier commit ; dernière modification des scripts : `c0805cf` du 02/03/2026) |
| Licence amont | Apache-2.0 (`LICENSE` amont ; aucun fichier `NOTICE`) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur ZPR natif (le `zbee_zdp` natif est un autre protocole) |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `zdp_dissector.lua` | Protocole `zdp` : en-tête ZDP, paquets de transit et de gestion |
| `link_header_dissector.lua` | Protocole `zdp_link_p2p` : octet de sens d'un lien point à point |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête. Le reste du dépôt (bibliothèque
Rust, schémas IDL) n'est pas importé.

## Utilisation

Les scripts ne s'enregistrent sur aucun port ni aucune table : après les
avoir copiés dans le dossier `plugins` de Wireshark, les associer à un
type de lien utilisateur (Préférences › Protocols › DLT_USER, par exemple
`USER0` → `zdp`, ou `zdp_link_p2p` en en-tête avec `zdp` en charge
utile), puis filtrer avec `zdp`. Champs filtrables : `zdp.type`,
`zdp.streamid`, `zdp.seq_num`…

## Remarques

- Le README amont avertit d'un code en pré-version, susceptible de
  changer sans préavis.
- Utilise `bit.band` / `bit.rshift` (bibliothèque `bit` fournie par
  Wireshark 4.4 et plus) ; nombreuses fonctions et tables globales,
  comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
