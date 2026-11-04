# P25 CAI — APCO Project 25 (interface radio)

Dissecteur Wireshark Lua des trames **APCO Project 25 Common Air
Interface** (radio professionnelle numérique FDMA), telles qu'op25 les
transmet en UDP (port 23456, option `-W` de `rx.py`). Il traite la
synchronisation de trame et les symboles d'état, le NID (NAC, DUID) et les
unités de données : HDU (MI, MFID, ALGID, KID, groupe de conversation), TDU,
LDU1 et LDU2 (trames vocales IMBE, Link Control, Encryption Sync, LSD), TSDU
(blocs TSBK) et TDU avec Link Control. C'est un portage en Lua de
`packet-p25cai.c` d'op25 (issue #508).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/ryanchapman/p25_wireshark (`lua/p25cai.lua`), **dépôt archivé** |
| Commit importé | `3d3c4492e11e02f7ebbda1adf5386d746438c425` du 10/03/2026 (dernier commit de la branche par défaut `main`) ; dernière modification de `p25cai.lua` : commit `c1da792aebfeb9e4d476f9956b4e972146a664f6` du 26/05/2025 |
| Licence amont | GPL-2.0 ou toute version ultérieure (en-tête du fichier, d'après `packet-p25cai.c`, © 2008 Michael Ossmann) ; `LICENSE` du dépôt = texte de la GPLv2. Compatible avec la licence de ce dépôt (GPL-3.0-or-later) |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur P25 CAI dans `tshark -G protocols` |

Texte complet de la licence : fichier `LICENSE` de ce dossier (copie
conforme du `LICENSE` amont). Le script est repris tel quel (aucune
modification de code) ; seule l'en-tête de provenance de cinq lignes est
ajoutée en tête (convention du dépôt, issue #563).

Dissecteurs voisins dans ce dépôt : `dfsi-cai` (CAI transporté en RTP par
l'interface DFSI) et `quantar-sqd` (liaisons V.24 des stations Quantar).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/p25cai.lua` | Protocole `p25cai` (« P25 CAI ») sur UDP 23456 ; préférences `p25cai.port`, `p25cai.enabled` et `p25cai.debug` |

## Utilisation

Le script exige le module **`inspect.lua`** (https://github.com/kikito/inspect.lua,
licence MIT), non fourni ici : sans ce module, le chargement échoue
(`module 'inspect' not found`, ligne 51). Le module est chargé mais n'est
utilisé nulle part dans le script. Copier `inspect.lua` et
`src/p25cai.lua` dans le dossier des plugins Lua personnels de Wireshark
(« Aide › À propos de Wireshark › Dossiers »), ou `inspect.lua` dans un
dossier du `package.path` de Lua, puis Ctrl+Maj+L. Le script exige
Wireshark 4.4 au minimum.

```sh
tshark -X lua_script:p25cai.lua -o p25cai.port:30000 -r capture.pcap -Y p25cai
```

Filtres : `p25cai`, `p25cai.hdu`, `p25cai.ldu1`, `p25cai.ldu2`,
`p25cai.tsbk`, `p25cai.lcf`, `p25cai.algid == 0x80` (clair),
`p25cai.algid == 0xaa` (ADP), `p25cai.imbe`.

## Vérification à l'import

tshark 4.6.4 (Lua 5.4), avec `inspect.lua` de kikito à côté du script.
Captures synthétiques UDP construites selon la structure lue par le script
(FS `5575f5ff77ff`, NID, mots de Golay 18,6 non corrigés, un symbole d'état
tous les 35 dibits) :

| Essai | Résultat |
|---|---|
| HDU en clair, MI `010203…09`, groupe 0x1234 | `Header Data Unit` ; ALGID `Unencrypted message (0x80)`, `Talk Group ID: … (4660) (0x1234)` ; **MI affiché `000203…09`** |
| HDU ADP, KID 0x00bb, groupe 0x0042 | ALGID `Motorola ADP (40 bit RC4) (0xaa)`, KID et groupe corrects ; premier octet du MI forcé à `00` |
| TDU (DUID 3) | `Terminator without Link Control` |
| DUID 9 | `Unknown Data Unit (0x09)` |
| Trame de 7 octets | laissée à UDP (moins de 14 octets) |
| HDU tronqué (40 octets) | arbre HDU vide, sans erreur affichée ; seul le journal de débogage montre `Range is out of bounds` |
| UDP 30000 | décodé seulement avec `-o p25cai.port:30000` |

LDU1, LDU2, TSDU et PDU n'ont pas été vérifiés (pas de capture op25
réelle).

## Limites constatées

- **Premier octet du MI toujours nul** : la fausse correction
  Reed-Solomon `rs_36_20_17_decode` (ligne 656) recopie les indices 1 à 15
  alors que le tampon du HDU commence à l'indice 0. `rs_24_12_13_decode`
  (Link Control des LDU1 et des TDU-LC) et `rs_24_16_9_decode`
  (Encryption Sync du LDU2, redéfinie ligne 1197) bouclent elles aussi de
  1 à n. Leur effet dépend de l'indexation de chaque appelant (lignes
  1130, 1275 et 1375) et n'a pas été vérifié.
- Aucune correction d'erreur : Golay, Hamming, cyclique et Reed-Solomon
  sont des extractions de bits (« Fake error correction decoders »,
  ligne 625), comme dans le C d'origine ; une trame bruitée est affichée
  telle quelle.
- **Journal de débogage sur la sortie standard** : niveau par défaut
  `Level 2` (ligne 63), soit une ligne `Lua[p25cai]: dissect() returned
  true` par paquet en plus des lignes de chargement. `-o
  p25cai.debug:Disabled` ne l'arrête pas, car `reset_debug_level`
  (ligne 111) ne remet jamais `dprint` à vide. Cela pollue les sorties
  `tshark` (`-T fields`, `-T json`…).
- Les erreurs de dissection sont absorbées par `pcall` (ligne 1619) : un
  paquet tronqué donne un arbre incomplet sans « Malformed Packet » ni
  info d'expert.
- PDU (DUID 0xC) non décodé (ligne 1592) ; champs source et destination
  du LDU1 non extraits (TODO amont) ; seul l'UDP d'op25 est pris en charge,
  sans heuristique.
- Fonctions définies deux fois (`cyclic_16_8_5_decode` lignes 639 et 1150,
  ainsi que `rs_24_16_9_decode` et `hamming_10_6_3_decode`) ; variables
  globales `build_term_lc_tvb`, `byte_to_binary`, `print_tvb_bytes`,
  `ptbf_item`.
