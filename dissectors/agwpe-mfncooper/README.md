# AGWPE — interface TCP des modems paquets radio

Dissecteur Wireshark Lua du protocole AGWPE (AGW Packet Engine) :
l'interface TCP par laquelle les applications de radio paquet (APRS,
BBS, Winlink…) pilotent un modem logiciel ou un TNC (AGWPE, Direwolf,
ldsped…). Le script décode l'en-tête de 36 octets (port, type de
données, PID, indicatifs émetteur et destinataire, longueur), distingue
requêtes et réponses selon le port du serveur, puis décode les données
de chaque type : connexion, version, ports, capacités, stations
entendues, trames surveillées, données connectées, digipéteurs, et
trames AX.25 brutes confiées au dissecteur AX.25 natif. TCP 8000 par
défaut (issue #946). Auteur : Martin F N Cooper, KD6YAM.

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/mfncooper/dissect-agwpe (`agwpe.lua`, version 1.0.0) |
| Commit importé | `e499ba2e3023d956663b18f78d4c058ead65716e` du 13/07/2025 (dernier commit de la branche par défaut `main`, qui est aussi la dernière modification du fichier) |
| Licence amont | MIT : `LICENSE` du dépôt (© 2025 Martin F N Cooper) et en-tête du script (« License: MIT License ») |
| Natif Wireshark 4.6.4 | Non : AX.25 et KISS sont natifs, mais aucun dissecteur AGWPE dans `tshark -G protocols` |

Texte de la licence : fichier `LICENSE` de ce dossier (copie conforme
du `LICENSE` amont). Le fichier est repris tel quel (aucune
modification) ; seule l'en-tête de provenance de cinq lignes est ajoutée
en tête de `agwpe.lua` (convention du dépôt, issue #563).

## Fichiers

| Fichier | Rôle |
|---|---|
| `src/agwpe.lua` | Types de données côté client (ligne 47) et côté serveur (ligne 69) ; champs `agwpe.*` (ligne 87) ; décodage des données des requêtes (ligne 332) et des réponses (ligne 359) ; contrôle de l'en-tête (ligne 451) ; protocole `agwpe` (ligne 464) ; dissection d'une trame (ligne 476) ; réassemblage TCP (lignes 545 et 554) ; préférences (ligne 562) ; inscription sur TCP 8000 ligne 594 |

## Utilisation

Copier `src/agwpe.lua` dans le dossier des plugins Lua personnels
(`~/.local/lib/wireshark/plugins/`), ou le charger par
`-X lua_script:agwpe.lua`. Préférences (Protocols → AGWPE) :
`agwpe.server_port` (port du serveur, 8000 par défaut ; sert à
distinguer requêtes et réponses), `agwpe.strict_validation` (rejet des
en-têtes dont les octets réservés ne sont pas nuls, activé par défaut),
`agwpe.show_reserved`. Filtres : `agwpe`, `agwpe.kind`,
`agwpe.callfrom`, `agwpe.callto`, `agwpe.text_data`…

## Vérification à l'import

`luac5.4 -p` : OK. tshark 4.6.4, par `-X lua_script:` et dans le
dossier des plugins : chargement sans erreur. Le dépôt amont ne
contient aucune capture. Essais sur une capture synthétique (session
TCP vers le port 8000), non commitée, construite d'après la
[spécification AGWPE](https://www.on7lds.net/42/sites/default/files/AGWPEAPI.HTM)
citée par l'auteur :

| Essai | Résultat |
|---|---|
| Requête et réponse `R` (version 2005.127) | « Major Version: 2005 » puis « Major Version: 127 » (la version mineure porte le nom de la majeure) |
| Réponse `G` « 2;Port1 Direwolf;Port2 TNC-Pi; » | « Port Count: 2 » et les deux noms de port |
| `X` (enregistrement d'indicatif) | « Registered: True (1) » |
| `M` (UNPROTO, PID 0xF0) | « Unproto Data: Bonjour APRS » |
| `U` (trame surveillée, « Len=12 ») | Texte d'en-tête jusqu'au `\r`, puis les 12 octets en « Binary » (le texte « Bonjour Hgn! » n'est pas affiché en clair) |
| `H` (station entendue avec deux SYSTEMTIME) | « First Heard: 2026-11-02 11:00:00 », « Last Heard: 2026-11-02 12:00:00 » |
| `g` (capacités du port) | Débit, TXDelay, persistance, etc., « Bytes Received: 12345 » |
| `K` (trame AX.25 brute APRS) | AX.25 natif : « Src: F4XYZ, Dst: APRS », UI |
| `v` (connexion par deux digipéteurs) | « Via 1: WIDE1-1 », « Via 2: WIDE2-1 » |
| `P` (connexion de l'application) | « User Id: utilisateur », « Password: motdepasse » (en clair, filtrable par `agwpe.password`) |
| Deux trames `y` et `Y` dans un même segment TCP | Deux arbres AGWPE |
| Octet réservé non nul | Trame laissée à TCP ; décodée avec `agwpe.strict_validation:FALSE` |

## Limites constatées

- La colonne Info n'est pas renseignée : elle garde le texte de TCP
  (« 40000 → 8000 [PSH, ACK]… »).
- La version mineure de la réponse `R` est ajoutée au champ
  `agwpe.version_major` (ligne 362) : le champ `agwpe.version_minor`
  n'est jamais rempli.
- `add_port_info` lit la variable globale `header` (ligne 256), laissée
  par `get_total_length`, au lieu de l'en-tête de la trame en cours ;
  d'autres variables sont globales (`text`, `binary`, `port_len`,
  `dissect_one`, `get_total_length`).
- Les données des trames surveillées (`I`, `S`, `U`, `T`) sont affichées
  en octets bruts, sans décodage AX.25 ni texte.
- Le sens requête/réponse dépend uniquement du port du serveur
  (ligne 488) ; une capture sur un autre port doit être déclarée dans
  la préférence.
- Les champs des digipéteurs s'appellent `agwpe.var1` à `agwpe.var7`
  (ligne 183), et non `agwpe.via1`…
- Le mot de passe de la requête `P` est affiché en clair (c'est le
  protocole qui le transmet ainsi).
