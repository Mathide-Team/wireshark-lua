# Trimble GSOF — sortie GNSS des récepteurs Trimble (Ryanf55)

Dissecteur Wireshark Lua du format Trimble GSOF (« General Serial Output
Format »), sortie de position, de navigation inertielle et de qualité
des récepteurs GNSS Trimble (par exemple le PX-1). Le script décode la
trame DCOL (« Data Collector Format »), le paquet GENOUT (type `0x40`)
qu'elle transporte, puis les enregistrements GSOF qu'il contient
(issue #541).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/Ryanf55/trimble-gsof-wireshark (`gsof.lua`) |
| Commit importé | `3cc025178def1f848ef0deb03463aac2679e0bee` du 30/05/2025 (dernier commit de la branche par défaut) ; dernière modification du script : commit `22b5fe8941ec4110de062a1ddd13b4e883907b12` du 30/05/2025 |
| Licence amont | MIT (`LICENSE` amont, © 2025 Ryan) ; aucune mention de licence dans le script. Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur GSOF, DCOL ou GENOUT dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/gsof.lua` | Protocoles `DCOL`, `GENOUT` et `GSOF` (lignes 7, 10 et 13), champs `dcol.*`, `genout.*` et `gsof.*` (lignes 16 à 106) ; dissecteurs aux lignes 275 (GSOF), 304 (DCOL) et 384 (GENOUT) ; inscrit sur le port UDP 44444 (ligne 411) |

## Utilisation

Copier `src/gsof.lua` dans le dossier des plugins Lua personnels de
Wireshark (« Aide › À propos de Wireshark › Dossiers »), puis recharger
avec Ctrl+Maj+L. Le récepteur doit envoyer sa sortie GSOF en UDP sur le
port 44444 (réglage décrit dans le README amont). Pour un autre port :
« Décoder comme » › DCOL. Filtres : `dcol`, `genout`, `gsof`,
`gsof.record_type`, `gsof.postime.*`, `gsof.ins.*`, `gsof.ins_rms.*`,
`gsof.llh_msl.*`.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins (sortie identique) : aucun
message au chargement. Le dépôt amont ne contient aucune capture (deux
copies d'écran seulement). Essais sur une capture synthétique construite
d'après la documentation Trimble (DCOL : STX `0x02`, état, type, longueur,
somme de contrôle, ETX `0x03` ; GSOF gros-boutiste), non commitée :

| Essai | Résultat |
|---|---|
| GENOUT avec enregistrements 1 (Position Time) et 49 (INS Full Navigation) | « GPS Time (ms): 345600000 », « GPS Week Number: 2400 », 12 satellites ; latitude 48.8156, longitude 7.7905, altitude 150.25, vitesses, attitude, vitesses angulaires et accélérations exactes |
| Enregistrement 50 (INS RMS) | les neuf écarts types décodés (0.1 à 0.9) |
| Enregistrement 70 (Lat, Long, MSL Height) | la latitude s'affiche « FOO » ; longitude en radians (0.13597), hauteur 150.25, modèle « EGM96 » |
| Deux trames DCOL dans un datagramme, la première de type `0x4B` | deux « DCOL Packet » ; charge `0x4B` en octets bruts, la seconde décodée |
| ETX faux | avertissement « Missing ETX (0x03) » |
| Datagramme de 2 octets | colonne DCOL, avertissement « Truncated DCOL packet » sans arbre |
| Longueur d'enregistrement supérieure aux données | avertissement « Truncated GSOF Record » |
| Filtres `gsof.record_type`, `gsof.postime.gps_week_number`, `gsof.ins.latitude`, `gsof.llh_msl.height`, `dcol.status`, `genout.page_index` | trames attendues sélectionnées |

## Limites constatées

- Seuls les enregistrements 1, 49, 50 et 70 sont détaillés. Les types 2
  à 8 sont nommés (lignes 109 à 125) mais leurs données ne sont pas
  décodées. L'enregistrement 1 s'arrête après le nombre de satellites
  (lignes 127 à 136) : les octets de drapeaux et le compteur
  d'initialisation ne sont pas affichés.
- Enregistrement 70 : la latitude est remplacée par le texte de mise au
  point « FOO » (ligne 246, variable globale `lat_item` ligne 245). La
  ligne 243 lit la valeur en petit-boutiste sans l'utiliser.
- `gsof_proto.fields` est réaffecté cinq fois (lignes 43 à 106) ; les
  filtres fonctionnent quand même sous 4.6.4. Le champ
  `gsof.record_name` (ligne 39) n'est jamais rempli.
- La somme de contrôle DCOL n'est pas vérifiée. Les pages GENOUT
  multiples (`page_index` / `max_page_index`) ne sont pas réassemblées.
  Un paquet GENOUT de moins de 7 octets est ignoré sans avertissement
  (ligne 385).
- Le paquet GENOUT apparaît deux fois imbriqué dans l'arbre (« GENOUT
  Packet » dans « GENOUT Packet »).
- Pas d'heuristique : seul le port UDP 44444 est reconnu ; rien n'est
  prévu pour la liaison série ou TCP.
