# TAK — Cursor-on-Target / TAK Protocol

Dissecteur Wireshark Lua des messages **TAK** (Team Awareness Kit)
au format **Cursor-on-Target** (CoT), par
Joshua M. Keyes (version 1.0.0). Protocole `tak` sur TCP et UDP, port
6969 par défaut (préférence) : il distingue trois formes et indique
version, longueur et forme dans l'arbre :

- **XML** (« version 0 ») : message commençant par `<?xml`, passé au
  dissecteur XML natif ;
- **stream** (version 1 implicite) : octet magique 0xBF + longueur en
  varint + charge Protobuf ;
- **mesh** : 0xBF + version en varint + 0xBF + charge Protobuf.

Les charges Protobuf sont passées au dissecteur Protobuf natif comme
message `atakmap.commoncommo.protobuf.v1.TakMessage` (préférence).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/jmkeyes/wireshark-tak-plugin (fichier `tak.lua`) |
| Commit importé | `3729c1c7d1c006f75a06d07e52f18de278e93a4c` du 31/01/2025 (branche `main`, dernier commit, qui est aussi la dernière modification du script) |
| Licence amont | MIT (fichier `LICENSE.md` amont, « Copyright (c) 2025 Joshua M. Keyes », copié ici sous le nom `LICENSE`) ; le script n'a pas d'en-tête de licence |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur TAK / CoT natif (XML et Protobuf sont natifs) |

## Fichiers

| Fichier | Rôle |
|---|---|
| `tak.lua` | Protocole `tak`, TCP/UDP 6969 par défaut |
| `LICENSE` | Licence MIT amont |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête.

## Utilisation

1. Copier `tak.lua` dans le dossier `plugins` de Wireshark.
2. Télécharger les fichiers `.proto` TAK (dépôt
   https://github.com/deptofdefense/AndroidTacticalAssaultKit-CIV,
   dossier `commoncommo/core/impl/protobuf`) dans un dossier ajouté aux
   chemins de recherche Protobuf (Préférences → Protocols → ProtoBuf) ;
   ils ne sont pas fournis ici.
3. Ajuster si besoin le port dans Préférences → Protocols → TAK, puis
   filtrer avec `tak`.

## Remarques

- Défaut amont relevé à la lecture : dans `prefs_changed`, le type de
  message est recopié depuis `tak.message_type` au lieu de
  `tak.prefs.message_type` ; après toute modification des préférences, le
  type Protobuf devient probablement `nil` et le décodage de la charge
  échoue (non vérifié).
- Pas de réassemblage TCP : en mode stream, la longueur annoncée doit
  correspondre exactement au reste du paquet, sinon une alerte
  « Payload length mismatch! » est émise.
- Le protocole `tak` est une variable globale.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
