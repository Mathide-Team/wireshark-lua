# Niagara Fox (automatisation des bâtiments)

Dissecteur Wireshark Lua du **protocole Fox** de Tridium, protocole
textuel utilisé par les équipements et stations **Niagara Framework**
(gestion technique de bâtiments) pour communiquer, généralement sur TCP
1911 (et 4911 en TLS) : séquence magique `fox `, type de trame
(asynchrone, synchrone, keep-alive, réponse, erreur), numéros de
requête et contenu textuel structuré (messages, clés / valeurs).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/MartinoTommasini/foxdissector |
| Commit importé | `2d04b9173dadbc32ba14412e253868da8e957477` du 02/07/2021 (branche `main`, dernier commit) |
| Licence amont | GPL-3.0-only (`LICENSE` amont : texte de la GPL v3, sans mention « or any later version » ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur Fox / Niagara dans la branche `release-4.6` des sources Wireshark |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `fox.lua` | Dissecteur `fox` (heuristique TCP + entrée « Décoder comme ») |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `fox.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`) ou lancer
`wireshark -X lua_script:fox.lua capture.pcap`, puis filtrer avec `fox`.
Le dissecteur heuristique reconnaît les flux TCP commençant par `fox ` ;
sinon, utiliser « Décoder comme… » sur le port concerné.

## Remarques

- Pas de port fixe : la table `tcp.port` reçoit l'entrée 0 (pour « Décoder
  comme ») et la détection se fait par heuristique.
- Le trafic Fox chiffré (foxs, TLS) n'est lisible qu'après déchiffrement
  TLS dans Wireshark.
- Variable globale `fox` (objet `Proto`) comme dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
