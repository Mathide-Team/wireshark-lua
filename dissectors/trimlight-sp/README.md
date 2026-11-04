# Trimlight Select Plus (éclairage LED permanent)

Dissecteur Wireshark Lua du **protocole local Trimlight Select Plus**
(contrôleurs d'éclairage LED de façade Trimlight), entre l'application
mobile et le contrôleur sur TCP 8189 : drapeau de début, type de requête,
longueur, puis charge utile selon la commande (motifs de bibliothèque, nom,
catégorie, mode d'effet, vitesse, luminosité, couleurs, planification…),
avec liaison requête ↔ réponse et contrôle du drapeau de fin.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/msjarrett/trimlight (fichier `protocol/TrimlightSP.lua`) |
| Commit importé | `3c16e54cfcabdff9f6e965e336dafbafcace8e3d` du 23/11/2023 (branche `main`, dernier commit ; dernière modification du dissecteur : `20a28ef` du 22/11/2023) |
| Licence amont | MIT (`LICENSE` amont, © 2020 Michael Jarrett) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Trimlight natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `TrimlightSP.lua` | Dissecteur `TRIMLIGHTSP` (TCP 8189) |
| `captures/msjarrett-trimlight1.pcapng` | Capture d'exemple amont (18 Ko) |
| `captures/msjarrett-trimlight2.pcapng` | Capture d'exemple amont (23 Ko) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier Lua. Non importés : la grosse
capture `nexus-bytes-trimlightSP-full.pcapng` (2 Mo), les traces texte
`matthewg-capture-01/`, la description du protocole `protocol/protocol.md`
et les outils Java / Python (proxy) du dépôt.

## Utilisation

Copier `TrimlightSP.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
ouvrir une capture de `captures/` et filtrer avec `trimlightsp`.

## Remarques

- Utilise la bibliothèque `bit` (fournie par Wireshark), pas `bit32`.
- Le sens requête/réponse est déduit du port de destination 8189.
- Ne décode pas l'API cloud Trimlight récente (Trimlight Edge), seulement
  le protocole LAN du Select Plus.
- Non vérifié dans Wireshark (pas de tshark dans l'environnement de test).
