# Xiaomi MiIO (protocole binaire local Mi Home)

Dissecteur Wireshark Lua du **protocole binaire MiIO de Xiaomi** (appareils
Mi Home : aspirateurs, purificateurs, prises, lampes…) sur UDP 54321 :
octets magiques 0x2131, longueur, champ inconnu, identifiant d'appareil,
horodatage, somme MD5, puis charge chiffrée en AES-128-CBC. Les paquets
« Hello » / « Hello Ack » (découverte) sont signalés ; si le **jeton de
l'appareil** (128 bits, en hexadécimal) est saisi dans les préférences, la
charge JSON est déchiffrée et affichée dans la colonne Info.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/0x5e/miio-dissector (fichier `miio.lua`) |
| Commit importé | `4ef5a80bbdcde45aee981ef413b10b38d080758f` du 07/08/2022 (branche `main`, dernier commit ; dernière modification du dissecteur : `758489c` du 07/08/2022) |
| Licence amont | MIT (`LICENSE` amont, © 2022 gaosen) |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur MiIO natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `miio.lua` | Dissecteur `miio` (UDP 54321), préférence « Device token » |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier. Non importés : `install.sh` et la
capture d'écran du README amont.

## Utilisation

Copier `miio.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), redémarrer Wireshark, saisir le
jeton dans Préférences → Protocoles → MIIO, puis filtrer avec `miio`.

## Remarques

- **Déchiffrement par commandes externes** : MD5 et AES sont calculés en
  lançant `xxd` et `openssl` via `io.popen` (shell) à chaque paquet chiffré.
  Il faut ces deux outils dans le `PATH` ; c'est lent sur de grosses
  captures, et le jeton saisi est inséré tel quel dans la commande shell
  (ne saisir qu'un jeton hexadécimal).
- L'auteur indique macOS seulement (Linux non testé, Windows non pris en
  charge). Avec OpenSSL 1.1 / 3, `openssl md5` affiche « MD5(stdin)= … »
  au lieu du seul condensat, ce qui fausserait la clé dérivée (non vérifié).
- Sans jeton, la charge reste affichée chiffrée ; le jeton est une donnée
  sensible de l'appareil, à ne pas partager avec les captures.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
