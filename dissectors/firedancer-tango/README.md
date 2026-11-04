# Firedancer Tango — messages internes du validateur Solana

Dissecteur Wireshark Lua des **fragments Tango** de
[Firedancer](https://github.com/firedancer-io/firedancer) (validateur
Solana) : Tango est la couche de messagerie entre les « tuiles » du
validateur (files `mcache` / `dcache`). Le script décode les
métadonnées d'un fragment (numéro de séquence, signature, chunk, taille,
contrôle début / fin de message, horodatages d'origine et de publication,
hachage du lien avec son nom : `net_quic`, `quic_verify`, `verify_dedup`,
`resolv_pack`, `poh_shred`…), puis la charge utile selon le lien :
transactions `fd_txn_t` / `fd_txn_m_t`, messages PoH → shred, remises de
CU (`fd_pack_rebate_t`), « became leader », « done packing », trames
Ethernet ou paquets TPU Solana.

Prévu pour des captures en DLT utilisateur (User 0, 147) ; enregistre
aussi le dissecteur TPU Solana sur le port UDP 9001.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/firedancer-io/firedancer (fichier `contrib/tango.lua`) |
| Commit importé | `300acc6fdcce505957d828bdcf9bc070b78cd9ce` du 01/11/2026 (branche `main`, dernier commit ; dernière modification de `tango.lua` : `d44b459` du 23/10/2026) |
| Licence amont | Apache-2.0 (fichier `LICENSE` : « Copyright 2022 Firedancer Contributors », Apache 2.0, suivi des licences des bibliothèques tierces du dépôt, copié ici tel quel ; `set_plugin_info` du script : `license = "Apache-2.0"`, auteur Philip Taffet) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Firedancer / Tango natif |

## Fichiers

| Fichier | Rôle |
|---|---|
| `tango.lua` | Protocole `fd_tango` (« Tango Frag ») et sous-protocoles `fd_txn_t`, `fd_txn_m_t`, `fd_poh_shred`, `fd_pack_rebate_t`, `fd_became_leader_t`, `fd_done_packing_t` |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

1. Installer aussi le dissecteur Solana, déjà présent dans ce dépôt :
   `dissectors/solana/src/solana.lua` (import de
   firedancer-io/solana_dissector, **GPL-2.0-only**), dans le même dossier
   `plugins` que `tango.lua`.
2. Copier `tango.lua` dans le dossier `plugins` de Wireshark.
3. Préférences → Protocols → DLT_USER → Edit… : ajouter une ligne
   « User 0 (147) » avec le dissecteur de charge utile `fd_tango`.
4. Ouvrir une capture des fragments Tango (format produit par les outils
   Firedancer), puis filtrer avec `fd_tango`.

## Remarques

- **Dépendance obligatoire** : en fin de script,
  `Dissector.get("solana.tpu.udp")` est appelé au chargement ; sans le
  dissecteur Solana chargé avant (ordre alphabétique `solana.lua` <
  `tango.lua` dans un même dossier), le chargement de `tango.lua` échoue.
- Les structures suivent l'état du code Firedancer au commit importé ;
  elles peuvent changer avec les versions suivantes.
- Utilise `bit.rshift` (bibliothèque `bit` fournie par Wireshark 4.4 et
  plus). Pas de capture d'exemple amont ; non vérifié dans Wireshark.
