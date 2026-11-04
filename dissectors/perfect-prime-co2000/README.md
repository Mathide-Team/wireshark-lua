# Perfect Prime CO2000 — enregistreur USB CO₂ / température / humidité

Dissecteur Wireshark Lua du **protocole USB de l'enregistreur Perfect
Prime CO2000** (aussi vendu sous la référence HT2000) : sur les trames de
32 octets, décodage de la température (°C), de l'humidité relative (%)
et de la concentration en CO₂ (ppm). Le script s'enregistre dans la table
`usb.control` (classes `0xff` et `0xffff`) et documente en commentaire le
format de la charge et l'identifiant USB (`10c4:82cd`).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/vortextube/Perfect-Prime-CO2000 |
| Commit importé | `09c98a03425359b2d8712a0dd5790ae568585638` du 17/01/2017 (branche `master`, dernier commit, qui est aussi la dernière modification de `co2000.lua`) |
| Licence amont | GPL-3.0-or-later (`LICENSE` GPL v3 ; en-tête : « either version 3 of the License, or (at your option) any later version », © 2016 Charles Robert Hill) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur CO2000 / HT2000 natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `co2000.lua` | Protocole `co2000` sur la table `usb.control` |

Fichier importé tel quel (fins de ligne CRLF conservées) ; seule une
en-tête SPDX + provenance de quatre lignes a été ajoutée en tête.

## Utilisation

Lancer `wireshark -X lua_script:co2000.lua capture-usb.pcapng` (usage
amont) ou copier le fichier dans le dossier `plugins` de Wireshark, puis
filtrer avec `co2000`.

## Remarques

- **Ne se charge probablement pas tel quel dans Wireshark 4.x** : le
  script appelle `Field.new("usb.endpoint_number.endpoint")`, champ
  supprimé des versions récentes (remplacé par
  `usb.endpoint_address.number`) ; or `Field.new` sur un champ inconnu
  déclenche une erreur au chargement. La variable obtenue n'est pas
  utilisée : contournement local, supprimer cette ligne ou y mettre
  `usb.endpoint_address.number` (code amont non modifié ici).
- Les valeurs sont des éléments texte, non filtrables ; l'alarme décrite
  en commentaire n'est pas décodée.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
