# LIFX LAN — ampoules LIFX (variante modulaire MinervasRefuge, inachevée)

Dissecteur Wireshark Lua du **protocole LAN actuel des ampoules LIFX**
(documentation officielle LIFX LAN), découpé en modules : en-tête de
trame (taille, protocole, adressable, étiqueté, origine, source),
adresse de trame (cible, drapeaux d'acquittement / réponse, séquence) et
en-tête de protocole (type de message), puis modules par famille de
messages — découverte (`service`), appareil (`device`, avec table des
produits LIFX), lumière (`light`), multizone, relais, tuiles. Port UDP
56700. **Travail en cours selon l'amont** : seuls quelques messages sont
réellement décodés et testés (`GetVersion` / `StateVersion`,
`SetColour`, `LightState`…).

## Import

| | |
|---|---|
| Dépôt amont | https://codeberg.org/MinervasRefuge/LIFX-Wireshark (dossier `src/`) |
| Commit importé | `49b1a390abb75f264dd3e5dd824c0c40c9272e72` du 11/06/2022 (branche `main`, dernier commit ; dernière modification de `src/` : `1278c72` du 11/06/2022) |
| Licence amont | GPL-3.0-only (fichier `COPYING` GPL v3, copié ici sous le nom `LICENSE` ; aucun en-tête ni mention « or later ») |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur LIFX natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme du `COPYING` amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `Lifx.lua` | Point d'entrée : protocole `lifx` sur UDP 56700, en-têtes, chargement des modules par `require` |
| `util.lua` | Fonctions communes (`LDMOD`, groupes de champs, pourcentages) |
| `service.lua`, `device.lua`, `light.lua`, `multizone.lua`, `relay.lua`, `tile.lua` | Modules par famille de messages |
| `products.lua` | Table des produits LIFX (identifiants → noms) |

Fichiers importés tels quels ; seule une en-tête SPDX + provenance de
quatre lignes a été ajoutée en tête de chaque fichier. Non importés : le
`makefile` et le script vide `products-dumper.guile` (chaîne de
génération Lisp / Guile hors sujet).

## Utilisation

Les modules sont chargés par `require("device")`, `require("util")`… :
ils doivent être trouvables via `package.path`. Le plus simple est de
lancer Wireshark depuis ce dossier avec
`wireshark -X lua_script:Lifx.lua capture.pcapng` (le répertoire courant
fait partie du chemin par défaut). Ne pas copier les modules seuls dans
le dossier `plugins` : Wireshark y exécuterait chaque fichier comme un
plugin indépendant. Filtrer ensuite avec `lifx`.

## Remarques

- **Conflit** : `dissectors/lifx/`, `dissectors/lifx-magicmonkey/`,
  `dissectors/lifx-scheffler/` et ce dossier déclarent tous le protocole
  `lifx` sur le port 56700 ; n'en charger qu'un seul. Pour un décodage
  complet du protocole actuel, préférer `dissectors/lifx/`.
- Chargement via `require` non vérifié ; nombreuses variables globales,
  comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
