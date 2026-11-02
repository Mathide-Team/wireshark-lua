# Afedri SDR — protocoles de commande (TCP) et d'échantillons I/Q (UDP)

Dissecteur Wireshark Lua des récepteurs de radio logicielle Afedri
(SDR-Net, SDR-IP, AFE822x), écrit par Alex Shovkoplyas (VE3NEA). Deux
protocoles sur le port 50000 :

- `afedri` (TCP) : messages de commande, au format « NET » (élément de
  contrôle : fréquence, état du récepteur, gain RF, débit
  d'échantillonnage, taille des paquets…) ou au format « HID »
  (commandes génériques du micrologiciel, avec arguments et réponses) ;
- `afedri-iq` (UDP) : paquets d'échantillons I/Q 16 ou 24 bits (en-tête,
  numéro de séquence, premiers échantillons) (issue #950).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/VE3NEA/Afedri-Dissector (`afedri.lua`) |
| Commit importé | `c05ac838f6bd06ae69ddade3d33bfdcd0c9767c3` du 05/09/2018 (dernier commit de la branche par défaut `master`, qui est aussi la dernière modification du fichier) |
| Licence amont | MIT : `LICENSE` du dépôt (© 2018 Alex Shovkoplyas) ; l'en-tête du script porte le même copyright, sans nom de licence |
| Natif Wireshark 4.6.4 | Non : aucun dissecteur Afedri dans `tshark -G protocols` |

Texte de la licence : fichier `LICENSE` de ce dossier (copie conforme
du `LICENSE` amont). Le fichier est repris tel quel (aucune
modification ; fins de ligne CRLF conservées) ; seule l'en-tête de
provenance de cinq lignes est ajoutée en tête de `afedri.lua`
(convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/afedri.lua` | Protocoles `afedri-iq` et `afedri` (lignes 22 et 23, variables globales) ; dissecteurs UDP (ligne 26) et TCP (ligne 35) ; éléments de contrôle (ligne 201) ; en-têtes UDP (ligne 226) ; commandes HID (ligne 273) ; décodage des types de paramètres (lignes 381 à 528) ; inscription sur TCP et UDP 50000 (lignes 582 et 585) |

## Utilisation

Copier `src/afedri.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`), ou le charger par
`-X lua_script:afedri.lua`. Le trafic des ports TCP et UDP 50000 est
décodé. Le script n'a pas de champs filtrables : seuls `afedri` et
`afedri-iq` peuvent servir de filtres. Voir les limites : la partie
TCP ne fonctionne pas avec Wireshark 4.6.4.

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, par `-X lua_script:` et dans le
dossier des plugins : chargement sans erreur, protocoles `afedri` et
`afedri-iq` présents dans `tshark -G protocols`. Le dépôt amont ne
contient aucune capture. Essais sur deux captures synthétiques (UDP et
TCP 50000), non commitées :

| Essai | Résultat |
|---|---|
| UDP, en-tête 0x8404, 1028 octets, 256 couples 16 bits | « header: 0x8404 (16-Bit data, large packet) », « sequence number: 1 », « I/Q data, 256 2x16-bit samples », 16 premiers couples puis « ... » |
| UDP, en-tête 0x8484, 388 octets | « 24-Bit data, small packet », « 64 2x24-bit samples » en hexadécimal |
| UDP, en-tête inconnu 0x1234, 104 octets, seul dans la capture | Erreur Lua « attempt to perform arithmetic on a nil value (global 'width') » (ligne 506) |
| Même paquet après un paquet 24 bits | Décodé avec la largeur du paquet précédent : « 16 2x24-bit samples » |
| TCP : SET_CONTROL_ITEM fréquence, état du récepteur, HID débit, réponse HID version | Erreur Lua « attempt to index a nil value (global 'bit32') » (ligne 42) sur chaque message |
| TCP, copie d'essai non commitée précédée d'une fonction `bit32.extract` | « CI_FREQUENCY », « frequency: 7,074,000 Hz » ; « RCV_START » ; « HID_GENERIC_SET_SAMPLE_RATE_COMMAND », « sampling rate: 192,000 Hz » ; « firmware version: 291 (0x0123) » |

## Limites constatées

- Le dissecteur TCP appelle `bit32.extract` (lignes 42, 43 et 458) : la
  bibliothèque `bit32` de Lua 5.2 n'existe pas dans Wireshark 4.6.4
  (Lua 5.4), et chaque message de commande provoque une erreur. Seul le
  protocole UDP des échantillons fonctionne tel quel.
- La largeur des échantillons est une variable globale (`width`,
  lignes 503 et 504), fixée seulement pour les quatre tailles de paquet
  connues : pour une autre taille, elle reste celle du paquet
  précédent, ou provoque une erreur s'il n'y en a pas.
- Toutes les fonctions et tables sont globales (`subtree`, `look_up`,
  `Gain`, `Frequency`…), ce qui peut entrer en conflit avec d'autres
  scripts.
- Aucun champ filtrable : les valeurs sont ajoutées comme texte.
- Pas de réassemblage TCP : plusieurs messages dans un même segment ne
  sont pas séparés.
- La commande HID 24 (`HID_GENERIC_SAVE_DST_IP_ADDRESS`, ligne 353)
  déclare son argument comme un octet, avec une étiquette mal placée.
- L'adresse MAC est reconstituée à partir de deux octets seulement
  (ligne 402), selon une convention propre à l'auteur.
