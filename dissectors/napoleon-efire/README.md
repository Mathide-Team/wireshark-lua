# Napoleon eFIRE (foyers et cheminées au gaz connectés, Bluetooth LE)

Dissecteur Wireshark Lua du **protocole eFIRE de Napoleon**, utilisé par
l'application mobile pour piloter en Bluetooth LE les foyers au gaz Napoleon
(module de contrôle W190-0090) : en-tête 0xAA (requête) / 0xBB (réponse),
type de message, longueur, commande — veilleuse, hauteur de flamme,
ventilateur, flux séparé, sortie auxiliaire, éclairage LED (état, couleur,
effets), minuterie, alimentation, mot de passe, synchronisation de l'heure,
versions BLE/MCU — puis paramètres, somme de contrôle XOR (vérifiée, avec
info experte) et octet de fin. Il s'appuie sur la dissection ATT
de Wireshark (handles 0x001E et 0x0020).

## Import

| | |
|---|---|
| Dépôt amont | https://github.com/kaechele/bonaparte (fichier `contrib/wireshark_efire.lua`) |
| Commit importé | `5090a35e36fd0db4bb8c62ba6ee6a0c0e17971ff` du 29/10/2026 (branche `main`, dernier commit ; dernière modification du dissecteur : `4d5e0c1` du 15/03/2023) |
| Licence amont | MIT (`LICENSE` amont, © 2023 Felix Kaechele ; en-tête du fichier : « (c) 2023 Felix Kaechele ») |
| Natif Wireshark 4.6.4 | Non — aucun dissecteur eFIRE natif |

Texte complet de la licence amont : fichier `LICENSE` de ce dossier (copie
conforme de l'amont).

## Fichiers

| Fichier | Rôle |
|---|---|
| `wireshark_efire.lua` | Dissecteur `efire` (table `btatt.handle`, handles 0x001E et 0x0020) |

Fichier importé tel quel ; seule une en-tête SPDX + provenance de quatre
lignes a été ajoutée en tête du fichier. Le reste du dépôt (bibliothèque
Python `bonaparte`, documentation du protocole Bluetooth) n'est pas importé.

## Utilisation

Copier `wireshark_efire.lua` dans le dossier `plugins` de Wireshark
(ex. `~/.local/lib/wireshark/plugins/`), recharger les plugins Lua, ouvrir
une capture Bluetooth LE (btsnoop Android, nRF Sniffer…) puis filtrer avec
`efire`.

## Remarques

- Les handles ATT 0x001E / 0x0020 sont ceux du module observé par l'auteur ;
  un autre firmware pourrait les déplacer (non vérifié).
- Utilise la bibliothèque `bit` (fournie par Wireshark), pas `bit32`.
- Pas de capture d'exemple amont ; non vérifié dans Wireshark.
