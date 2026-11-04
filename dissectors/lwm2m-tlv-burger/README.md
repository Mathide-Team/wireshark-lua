# LwM2M TLV — format TLV d'OMA Lightweight M2M (Burger-Scheidlin)

Dissecteur Wireshark Lua du **format TLV d'OMA LwM2M**, transporté dans
les charges CoAP des objets connectés : pour chaque élément, type
(instance d'objet, instance de ressource, ressources multiples, ressource
avec valeur), taille de l'identifiant et de la longueur, identifiant,
longueur et valeur, avec décodage récursif des éléments imbriqués. Le
script s'enregistre dans la table `media_type` pour le type de contenu
CoAP numérique 1542 (« Unknown Type 1542 »).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/cburger-scheidlin/Lwm2mTlvDissector |
| Commit importé | `d5fe61715c582ea273ae5a76b3b30df8fb7a8a9f` du 08/02/2016 (branche `master`, dernier commit ; dernière modification du script Lua : `c7426ef` du 20/12/2015) |
| Licence amont | GPL-2.0-only (`LICENSE` GPL v2 ; en-tête du fichier : « either version 2 of the License », sans clause « or any later version », © 2015 Christoph Burger-Scheidlin) |
| Natif Wireshark 4.6.4 | **Oui** — dissecteur natif `lwm2mtlv` (`packet-lwm2mtlv.c`), appelé par CoAP pour `application/vnd.oma.lwm2m+tlv` (11542), avec noms des objets et ressources OMA ; ce script est à considérer comme obsolète ou pédagogique |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `Lwm2mTlvDissector.lua` | Protocole `tlv` (« LWM2M TLV ») sur le type de contenu CoAP 1542 |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête. Le plugin C du même dépôt (`src/`, CMake)
n'est pas importé.

## Utilisation

Copier `Lwm2mTlvDissector.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `tlv`.

## Remarques

- Le numéro 1542 est celui des brouillons LwM2M de 2015 ; la valeur
  normalisée est 11542, déjà prise en charge par le dissecteur natif. Le
  script ne s'appliquera donc qu'à d'anciennes captures, ou après
  adaptation locale du type de contenu.
- Autre import du même format : `dissectors/lwm2m-tlv-tanganelli/`.
- Nom de protocole court `tlv` et fonctions globales (`parseTLV`…) comme
  dans l'amont.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
