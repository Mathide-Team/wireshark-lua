# Watt Stopper DLM / In Room Bus — commande d'éclairage (Legrand)

Dissecteur Wireshark Lua du **bus DLM / In Room Bus (IRB) de Watt
Stopper** (Legrand), réseau local des commandes d'éclairage de pièce
(interrupteurs, détecteurs de présence, variateurs, relais) : codes de
fonction (arbitrage, « Push n' Go » / « Push n' Learn », réglage,
lecture / écriture mémoire, état des charges, détecteurs, mesure de
puissance…), adresses source et destination, multidiffusion, données et
contrôle LRC. Le même fichier ajoute un sous-dissecteur des services
**BACnet PrivateTransfer** du fabricant n° 86 (Watt Stopper), utilisés
par les passerelles LMBC pour transporter des trames DLM. Le bus DLM
s'enregistre sur l'encapsulation `USER0`.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/kargs-net/kargs-net.github.io (fichier `captures/irb.lua`) |
| Commit importé | `c7f6b224d314da0d7bfe3711fee34cd3a693680e` du 31/05/2026 (branche `main`, dernier commit ; dernière modification de `captures/irb.lua` : `8728c53` du 24/12/2023) |
| Licence amont | MIT (`LICENSE` amont, © 2023 kargs-net ; en-tête : « Copyright Steve Karg ») |
| Natif Wireshark 4.6.4 | Non pour DLM / IRB ; BACnet (`bacapp`) est natif et ce script s'y greffe par la table `bacapp.vendor_identifier` |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `irb.lua` | Protocole `dlm` sur `USER0`, et `bacnet-pt` sur le fabricant BACnet 86 |

Le dépôt amont contient deux copies du script : `BACnet/irb.lua` et
`captures/irb.lua`. Seule la seconde, plus récente (même jour, quelques
minutes après) et plus complète (codes de fonction supplémentaires :
« Sensor Default », « Power Monitor High Resolution »…), est importée,
telle quelle, avec une en-tête SPDX + provenance de quatre lignes. Les
captures BACnet du dossier amont (dont des captures de plugfests
d'autres sociétés) et les présentations ne sont pas importées.

## Utilisation

Copier `irb.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, puis
filtrer avec `dlm` (captures du bus en `USER0`) ou `bacnet-pt` (services
PrivateTransfer Watt Stopper dans le trafic BACnet).

## Remarques

- Prend **toute** l'encapsulation `USER0` (DLT 147) tant que le script
  est chargé.
- Le commentaire d'origine vise Wireshark 1.6 ; non vérifié dans les
  versions récentes. Utilise `bit.band` (bibliothèque `bit` fournie par
  Wireshark 4.4 et plus).
- Le champ `irb.lrc` est déclaré par les deux protocoles (`dlm` et
  `bacnet-pt`), comme dans l'amont.
- Pas de capture DLM d'exemple importée ; non vérifié dans Wireshark.
