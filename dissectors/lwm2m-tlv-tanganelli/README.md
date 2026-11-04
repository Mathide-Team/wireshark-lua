# LwM2M TLV (dissecteur Lua historique)

Dissecteur Wireshark Lua **historique** (2015) de l'**encodage TLV de
LwM2M** (OMA Lightweight M2M, gestion d'objets connectés au-dessus de
CoAP) : il se substitue au dissecteur du port UDP 5683, appelle le
dissecteur CoAP d'origine, puis décode la charge en suite de TLV — type
(instance d'objet, instance de ressource, ressources multiples, ressource
avec valeur), longueur de l'identifiant, type de longueur, longueur et
valeur.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Tanganelli/wireshark-lwm2m (fichier `lwm2m.lua`) |
| Commit importé | `90dc5748aee8fb7abdd071595a5ba808abf1c470` du 29/12/2015 (branche `master`, dernier commit ; dernière modification du dissecteur : `7b3eabe` du 29/12/2015) |
| Licence amont | GPL-2.0-only (`LICENSE` amont : texte de la GPL v2, sans mention « or any later version » propre au projet ; pas d'en-tête de licence dans le fichier Lua) |
| Natif Wireshark 4.6.4 | **Oui** — dissecteur natif `lwm2mtlv` (`packet-lwm2mtlv.c`), appelé par CoAP pour le type de contenu `application/vnd.oma.lwm2m+tlv`, avec noms des objets et ressources OMA ; ce script Lua est à considérer comme obsolète ou pédagogique |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `lwm2m.lua` | Protocole `lwm2m` (remplace le dissecteur UDP 5683, puis rappelle CoAP) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier.

## Utilisation

Copier `lwm2m.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `lwm2m`. Dans la plupart des cas, le dissecteur natif
`lwm2mtlv` suffit (filtre `lwm2mtlv`).

## Remarques

- **`bit32` absent des Wireshark récents** : le décodage des octets de type
  appelle `bit32.band` et `bit32.arshift`, bibliothèque de Lua 5.2 absente
  par défaut de Lua 5.3 et 5.4, seules versions prises en charge depuis
  Wireshark 4.4 (qui fournit `bit` à la place). Sans `bit32` global, la
  dissection échoue dès le premier paquet CoAP avec charge (« attempt to
  index a nil value (global 'bit32') ») ; contournement local : ajouter
  `bit32 = bit` en tête du fichier (code amont non modifié ici) ;
- tente de décoder en TLV **toute** charge CoAP sur le port 5683, même au
  format texte, JSON, CBOR… (erreur affichée dans l'arbre, CoAP restant
  décodé — README amont) ; ne couvre pas CoAPS ni les autres ports ;
- variable globale `original_coap_dissector` comme dans l'amont ;
- pas de capture d'exemple amont ; non vérifié dans Wireshark.
