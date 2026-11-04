# Noise IK Mesh — poignée de main Noise_IK_25519_ChaChaPoly_BLAKE2b

Dissecteur Wireshark Lua du **protocole de transport « Noise Mesh »** du
projet bivex/Noise_IK_25519_ChaChaPoly_BLAKE2b (bibliothèque C de
sessions chiffrées pour réseau maillé d'objets connectés, fondée sur le
cadre Noise, motif IK, X25519, ChaCha20-Poly1305, BLAKE2b) : préfixe de
longueur sur 2 octets avec réassemblage TCP, puis identification du
message **d'après sa longueur** — initiation de la poignée de main
(96 octets : clé éphémère, clé statique chiffrée, étiquette Poly1305),
réponse (48), finalisation (45), réponse de transport (44) ou données
chiffrées — et sens client → serveur / serveur → client d'après les
ports. Ports TCP 7000 et 8000.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/bivex/Noise_IK_25519_ChaChaPoly_BLAKE2b (dossier `wireshark/`) |
| Commit importé | `44cf04b0d7e9ada98f24f40304fea001e75c79be` du 24/02/2026 (branche `main`, dernier commit, qui est aussi la dernière modification de `wireshark/noise_ik.lua`) |
| Licence amont | MIT — déclarée par l'auteur dans le README racine (« MIT License - See LICENSE file for details ») ; le fichier `LICENSE` annoncé est absent du dépôt et le script n'a pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non pour ce format ; WireGuard (natif `wg`) utilise aussi Noise IK, mais avec un autre format de trames |

L'amont ne fournit pas de texte de licence : texte de référence de la
licence MIT : https://spdx.org/licenses/MIT.html — à reproduire avec la
mention « Copyright (c) bivex » (titulaire du dépôt) en cas de
redistribution. Même situation que `dissectors/pqkem-coap/` (#184).

## Fichiers

| Fichier | Rôle |
|---|---|
| `noise_ik.lua` | Protocole `noise_ik` sur TCP 7000 et 8000 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Non importés : la bibliothèque C, les
tests et le script `test_dissector.sh` (lance serveur, client et
capture du projet).

## Utilisation

Copier `noise_ik.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer
`tshark -r capture.pcap -X lua_script:noise_ik.lua -Y noise_ik`.
Champs filtrables : `noise_ik.msg_type`, `noise_ik.length`,
`noise_ik.direction`…

## Remarques

- La classification des messages repose uniquement sur leur longueur :
  des données de transport de 96, 48 ou 45 octets seront prises pour des
  messages de poignée de main. Aucun déchiffrement.
- Le sens est déduit de la comparaison des ports source et destination.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
