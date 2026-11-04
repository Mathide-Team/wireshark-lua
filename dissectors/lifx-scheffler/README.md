# LIFX — ampoules Wi-Fi LIFX (protocole LAN v1, variante Scheffler)

Dissecteur Wireshark Lua du **protocole LAN historique des ampoules Wi-Fi
LIFX** : en-tête (taille, protocole, adresse cible, passerelle PAN,
horodatage, type de paquet) et charges utiles des messages (passerelle,
alimentation, étiquette, version et état des microprogrammes maillé et
Wi-Fi, informations Wi-Fi, état de la lampe — teinte, saturation,
luminosité, température —, étiquettes…). Ports TCP et UDP 56700.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/tscheffl/LIFX (dossier `Wireshark/`) |
| Commit importé | `db2d5826e760c5db5d5bac101d99b5a0a6a43a2f` du 13/02/2022 (branche `master`, dernier commit, qui est aussi la dernière modification de `Wireshark/lifx.lua`) |
| Licence amont | MIT (`LICENSE` amont, © 2022 Thomas Scheffler ; en-tête du fichier : © 2012 Mark Wolfe, 2022 Thomas Scheffler) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur LIFX natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `lifx.lua` | Protocole `lifx` sur TCP et UDP 56700 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le code C du dépôt (pilotage des ampoules)
n'est pas importé.

## Utilisation

Copier `lifx.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `lifx`.

## Remarques

- **Variante modifiée** du script de `dissectors/lifx-magicmonkey/`
  (magicmonkey/lifxjs, MIT) : même structure et mêmes noms, avec des
  types de messages complétés et numérotés. L'en-tête attribue le code
  d'origine à Mark Wolfe (wolfeidau/lifx) ; attribution reprise telle
  quelle.
- **Conflit** : `dissectors/lifx/`, `dissectors/lifx-magicmonkey/` et ce
  dossier déclarent tous le protocole `lifx` et le port 56700 ; n'en
  charger qu'un seul. Pour le protocole LAN actuel (v2), préférer
  `dissectors/lifx/`.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
