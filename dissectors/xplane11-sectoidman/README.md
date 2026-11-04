# X-Plane 11 — paquets UDP « DATA » (sectoidman)

Dissecteur Wireshark Lua des paquets UDP « DATA » du simulateur de vol
X-Plane 11. Ces paquets transportent, par blocs de 36 octets, les
groupes de données choisis dans le simulateur (vitesse, attitude,
position, moteurs…). Chaque bloc contient un numéro de groupe et huit
valeurs flottantes ; le script donne au numéro le nom du groupe (136
noms, de « Frame Rate » à « Motion platform stats ») (issue #774).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/sectoidman/literate-spork (`x-plane.lua`) |
| Commit importé | `7dcfd7daa7da4fb44c5b630e040dba9f2e386a7b` du 11/08/2017 (dernier commit de la branche par défaut) ; dernière modification du script : commit `fcd39c19d46d09d7d1ca7a428e088f3b17202019` du 11/08/2017 |
| Licence amont | GPLv2 (fichier `LICENSE` du dépôt, sans clause « or later » ; le script ne porte aucune mention de licence). Déclarée `GPL-2.0-only`, comme pour `dissectors/avionique` et `dissectors/gdl90-kyser` |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur X-Plane dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

Autres dissecteurs X-Plane de ce dépôt : `dissectors/xplane11-wegylexy/`
(#534, port 49001, paquets BECN, RPOS, RADR, RREF…) et
`dissectors/xplane-avacee/` (#535, heuristique, nombreux types de
paquets).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/x-plane.lua` | Protocole `x-plane` (« X-Plane UDP Data Protocol », ligne 6), table des 136 noms de groupes (lignes 8 à 145), dissecteur ligne 154 ; inscrit sur le port UDP 49000 (ligne 192) |

## Utilisation

Copier `src/x-plane.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis recharger
avec Ctrl+Maj+L. Les paquets sont reconnus sur le port UDP 49000 ; pour
le port de sortie réglé dans X-Plane (« Settings › Data Output »),
utiliser « Décoder comme » › X-PLANE. Le filtre `x-plane` sélectionne
les paquets ; le script ne déclare aucun champ filtrable.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : aucun message au chargement. Le
dépôt amont ne contient aucune capture. Essais sur une capture
synthétique (« DATA », octet interne, blocs de 36 octets en
petit-boutiste, valeurs inutilisées à -999), non commitée :

| Essai | Résultat |
|---|---|
| DATA avec les groupes 3, 17 et 20 | « Airspeed » (120.5, 121.0, 118.25, 140.0), « Attitude » (2.5, -1.25, 270.0), « Global Position » (48.815601348877, 7.790500164032, 1500.0) ; valeurs -999 masquées |
| Groupe inconnu (200) | « Unknown - 200 » |
| Paquet `RREF` | type, octet interne et longueur seulement |
| DATA dont la longueur n'est pas 5 + n × 36 | blocs complets décodés, puis **erreur Lua** ligne 177 (`Range is out of bounds`) |
| Paquet de 2 octets | **erreur Lua** ligne 157 |
| Chargé avec `xplane11-wegylexy` et `xplane-avacee` | le port 49000 revient à ce script (colonne « X-PLANE ») |

## Limites constatées

- Seuls les paquets « DATA » sont détaillés (ligne 164) ; les autres
  types (RREF, DREF, BECN…) n'affichent que leur en-tête.
- Le script n'ajoute que du texte (lignes 157 à 185) : aucun champ
  `ProtoField`, donc aucun filtre sur une valeur. Les huit valeurs d'un
  bloc s'appellent toutes « Data », sans unité ni nom.
- Pas de contrôle de longueur : erreur Lua sur un paquet court ou un
  bloc incomplet.
- « Length » donne la longueur totale du paquet, mais la ligne couvre
  les octets à partir du sixième (ligne 160).
- Fautes de frappe dans les noms : « GPS tatus » (ligne 112), « Marker
  staus » (ligne 114). `xplane_proto` et `udp_table` sont des variables
  globales.
- Seul le port 49000 est inscrit, sans préférence ni heuristique.
