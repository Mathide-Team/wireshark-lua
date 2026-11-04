# ka9q-radio — protocole de contrôle et d'état (ka9qctl)

Dissecteur Wireshark Lua fourni avec ka9q-radio, le récepteur de radio
logicielle multicanal de Phil Karn (KA9Q). Il décode les paquets de
contrôle et d'état échangés entre `radiod` et ses clients (`control`,
`monitor`…) : la classe du message (STATUS ou CMD), puis une suite de
TLV (type sur un octet, longueur au format BER). Il décode les entiers,
les flottants, les chaînes, les adresses de socket IPv4 et IPv6, les
listes et les heures GPS, sur UDP 5006 (issue #827).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ka9q/ka9q-radio (`share/ka9q_ctl.lua`) |
| Commit importé | `ad53ecd341c8464e5813e6feb66be37a1e966982` du 01/11/2026 (dernier commit de la branche par défaut `main`) ; dernière modification du fichier : commit `0c55fba1b832689451f95c37ecf8d14c37426bc9` du 08/10/2026 |
| Licence amont | GPL-3.0-only : `LICENSE.TXT` du dépôt (texte de la GPLv3, sans mention « or later » dans le dépôt) ; le script n'a pas d'en-tête de licence (« December 2025 KA9Q + ChatGPT »). Compatible avec la GPL-3.0 de ce dépôt |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur ka9q-radio dans `tshark -G protocols` |

Texte de la licence : fichier `LICENSE` de ce dossier (copie conforme
du `LICENSE.TXT` amont). Le fichier est repris tel quel (aucune
modification) ; seule l'en-tête de provenance de cinq lignes est ajoutée
en tête de `ka9q_ctl.lua` (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/ka9q_ctl.lua` | Protocole `ka9qctl` (« ka9q-radio Control/Status », ligne 25) ; préférences (lignes 28 à 30) ; champs `ka9qctl.*` (lignes 33 à 52) ; noms des 122 types de TLV (`STATUS_TYPE_NAME`, ligne 55) ; nature de chaque type (`TLV_KIND`, ligne 189) ; décodage par nature (ligne 670) ; dissecteur ligne 987 ; inscription sur UDP 5006 ligne 1087 |

## Utilisation

Copier `src/ka9q_ctl.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`). Le trafic du port UDP 5006 est
décodé ; la colonne Info affiche « STAT » ou « CMD », puis l'étiquette
de commande (`tag=`), le SSRC et l'heure GPS quand ils sont présents.
Filtres : `ka9qctl`, `ka9qctl.class`, `ka9qctl.tlv.type`,
`ka9qctl.sock.addr4`, `ka9qctl.string`…

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, script chargé par `-X lua_script:`,
puis copié dans le dossier des plugins : chargement sans erreur. Le
dépôt amont ne contient aucune capture. Essais sur une capture
synthétique (UDP 5006), non commitée ; le codage a été comparé à
`src/status.c` et `src/status.h` du même commit :

| Essai | Résultat |
|---|---|
| STATUS : COMMAND_TAG, DESCRIPTION, STATUS_DEST_SOCKET IPv4, RADIO_FREQUENCY (f64), OUTPUT_SAMPRATE, GPS_TIME, EOL | « STAT tag=1234 5678 2024-05-17 16:53:02.0 UTC » ; « 239.1.2.3:5006 », « 14 074 000.000 Hz », « 12 000 Hz » |
| CMD : COMMAND_TAG 7, RADIO_FREQUENCY 7,074 MHz | « CMD  tag=7 », « 7 074 000.000 Hz » |
| DESCRIPTION de 150 octets (longueur BER `81 96`) | Longueur 150, chaîne complète |
| TLV annoncé à 50 octets, 5 présents | Erreur « TLV type 4 length 50 overruns packet » |
| Type inconnu 200 | « (200) Unknown », valeur brute |
| RADIO_FREQUENCY de longueur 0 (zéro compressé par `radiod`) | « 0.000 Hz » |

## Limites constatées

- Six types que `status.h` marque aujourd'hui `UNUSED` portent encore
  leur ancien nom : 37 DOPPLER_FREQUENCY, 38 DOPPLER_FREQUENCY_RATE,
  81 GAINSTEP, 88 CONVERTER_OFFSET, 92 COHERENT_BIN_SPACING et
  103 BLOCKS_SINCE_POLL (lignes 93 à 159). Les types 118 à 121 s'écrivent
  « SWEEP RATE », « SWEEP DURATION »… avec une espace au lieu du `_` de
  `status.h` (lignes 174 à 177).
- La préférence « Float/Dbl are little-endian » est sans effet : elle
  est copiée dans une variable locale jamais lue (lignes 993 à 995), et
  les flottants sont toujours lus en gros-boutiste. C'est d'ailleurs le
  bon ordre : `status.c` (`encode_float`, `encode_double`) code les
  flottants comme des entiers gros-boutistes, zéros de tête supprimés,
  contrairement au commentaire de l'en-tête du script (« machine
  order »).
- L'avertissement « Extra … byte(s) after EOL » (lignes 1071 à 1077)
  ne peut jamais apparaître : la boucle s'arrête dès qu'elle lit un type
  0 (ligne 1015), avant d'atteindre ce contrôle. Les octets qui suivent
  EOL sont ignorés sans avertissement (essai : `00 aa bb` en fin de
  paquet).
- Aucun champ filtrable par type de TLV : la fréquence, le SSRC ou la
  description ne se filtrent qu'au travers des champs génériques
  (`ka9qctl.double`, `ka9qctl.uint`, `ka9qctl.string`).
- Seul le port UDP 5006 est inscrit ; `radiod` peut utiliser d'autres
  groupes et ports d'état selon sa configuration.
