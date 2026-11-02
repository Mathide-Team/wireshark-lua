# Dräger Infinity — diffusions UDP du réseau de surveillance

Dissecteur Wireshark Lua expérimental des diffusions UDP (port 2050) du
réseau de moniteurs patient Dräger Infinity, obtenu par rétro-ingénierie.
Il traite deux formes de trames, reconnues uniquement à leur longueur.
Les trames de 660 octets sont des messages d'alarme ou d'état : appareil,
alerte, nom du patient. Les trames de plus de 1000 octets portent les
mesures : fréquences respiratoire et cardiaque (ECG), SpO2 et pouls,
pression non invasive systolique, diastolique et moyenne, température
(issue #520).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/cbluoss/InfinityDissector (`Infinity.lua`, seul fichier du dépôt avec `LICENSE`) |
| Commit importé | `c60fdfa5fafd32c0ff6136e4c923edad985305f2` du 11/04/2021 (« fixed spo2 address », dernier commit de `main`, qui modifie aussi `Infinity.lua`) |
| Licence amont | AGPL-3.0 : `LICENSE` du dépôt (texte GNU AGPL v3 sans mention « ou ultérieure » de l'auteur, d'où `AGPL-3.0-only`). Combinaison avec la GPL-3.0 de ce dépôt permise par l'article 13 de la GPL v3 ; l'AGPL est déjà présente dans le dépôt (`dissectors/aerospike`) |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur Dräger Infinity dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/Infinity.lua` | Protocole `Infinity` (« Infinity Network Protocol ») sur UDP 2050 (ligne 102) ; champs `infinity.packet.*`, `infinity.message.*`, `infinity.patient.name`, `infinity.data.*` |

## Utilisation

**Le script ne se charge pas avec Wireshark 4.6.4.** Le nom de filtre
`infinity`, dérivé du nom de protocole déclaré ligne 6, est un mot
réservé des filtres d'affichage. tshark s'arrête dès le chargement
(« Dissector bug: Protocol filter name "infinity" is invalid because it
is a reserved keyword », code de sortie 8). Wireshark, qui partage ce contrôle, n'a pas été
essayé ; il faut s'attendre au même échec et retirer le greffon du
dossier des plugins.

Il ne peut servir qu'avec un Wireshark plus ancien qui accepte ce nom :
copier `src/Infinity.lua` dans le dossier des plugins Lua personnels,
puis Ctrl+Maj+L. Filtre : `infinity`. Autre port : `Decode As…`.

## Vérification à l'import

- `luac5.4 -p` : OK ; chargement dans tshark 4.6.4 : échec (voir
  ci-dessus).
- Pour comparer, une **copie hors dépôt** dont seul le nom du protocole a
  été changé (`InfinityLua`) a été chargée sur des captures UDP
  synthétiques construites d'après les décalages du script :

| Essai | Résultat |
|---|---|
| Trame de 660 octets (horodatage, appareil `Bed 12A`, alerte, nom `DUPONT^JEAN`) | `Packet timestamp`, `Packet length: 660`, `Is Message` exacts ; **`Device`, `Alert` et `Patient Name` illisibles** (caractères CJK : octets ASCII apparemment lus par paires, comme de l'UTF-16) |
| Trame de 1200 octets avec mesures (FR 16, FC 72, SpO2 98, pouls 71, PNI 120/80/93, 37,2 °C) | toutes les valeurs exactes (température `372`) |
| Même trame avec FC 150 | `Heart Rate (ECG): -106` (champ signé sur un octet) |
| Trame de 10 octets | **erreur Lua** ligne 71 (`Range is out of bounds`) |

## Limites constatées

- Nom de protocole réservé : inutilisable tel quel avec Wireshark 4.6.4.
- Ligne 60, `infinity_protocol.fields` est remplacé par une table de
  variables jamais définies (`RRsys`, `sPO2`…). La déclaration des
  lignes 7 à 56 est donc perdue ; dans la copie d'essai, les champs
  s'affichent malgré tout.
- Chaînes (lignes 76 à 78) passées comme valeurs Lua plutôt que comme
  plages du tampon : affichage illisible, pas de lien vers les octets.
- Mesures en entiers signés sur un octet (`ProtoField.int8`) : toute
  valeur au-delà de 127 (fréquence cardiaque, pression systolique) est
  négative.
- Type de trame déduit de la seule longueur (660 ou plus de 1000
  octets) ; aucun contrôle de longueur minimale (erreur Lua sur trame
  courte) ; tout trafic UDP 2050 est revendiqué.
- Décalages issus de la rétro-ingénierie d'une seule configuration
  d'appareils ; le commentaire de la ligne 43 indique `0x01FF` pour la
  SpO2, le code lit `0x00FF` (ligne 87, correction du dernier commit).
- Variables globales (`packet_length`, `spo2`, `length`…) ; colonne
  Info laissée à UDP ; pas de capture réelle disponible.
- Données de santé nominatives (nom du patient) en clair dans les
  trames : à manier avec précaution.
