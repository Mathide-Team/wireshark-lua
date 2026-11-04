# Maintenance des dissecteurs importés (issue #766)

Les dissecteurs de `dissectors/` sont des copies de dépôts tiers, figées au
commit indiqué dans leur `README.md` (tableau « Import », convention #563).
Ce document décrit comment repérer les amonts qui ont bougé et comment les
reprendre.

## Repérer les amonts modifiés

```sh
python3 scripts/verifier_mises_a_jour.py               # rapport Markdown
python3 scripts/verifier_mises_a_jour.py --json        # pour un outil
python3 scripts/verifier_mises_a_jour.py --strict      # code 1 s'il y a du travail
```

Pour chaque dissecteur, le script lit « Dépôt amont » (ou « Dépôt amont
importé ») et le premier SHA de « Commit importé ». Il interroge ensuite la
source avec `git ls-remote` : sur la branche citée (« dernier commit de
`main` », « branche `master` »…), sinon sur `HEAD`. Si la branche citée a
disparu, il se rabat sur `HEAD` et le signale.

Les états possibles :

- **À jour** : la pointe amont est le commit importé.
- **Amont modifié** : la branche a avancé ou a été réécrite.
- **Source injoignable** : le dépôt a été supprimé, renommé ou rendu privé, ou le réseau est en échec.
- **Hors forge git** : la source est en http/https/ftp (voir plus bas).
- **Provenance incomplète** : le README ne donne pas d'URL ou de SHA de 40 caractères.

Le workflow `Mises à jour amont` (`.github/workflows/mises-a-jour.yml`)
lance le script chaque lundi, ou à la demande (`workflow_dispatch`). Il
publie le rapport dans le résumé du job et en artefact. Il ne bloque rien et
n'importe rien.

## Reprendre une mise à jour

1. Ouvrir (ou réutiliser) une issue « mise à jour de `<dissecteur>` ». Y
   citer le commit importé et la nouvelle pointe.
2. Comparer les seuls chemins importés : `git diff <importé> <pointe> -- <chemins>`.
   Les chemins sont listés dans la colonne « Dépôt amont » et la section
   « Fichiers » du README. Un monodépôt (EVerest, firedancer, bitcoin-abc…)
   avance souvent sans toucher au dissecteur. Dans ce cas, mettre à jour le
   seul « Commit importé » (avec la date), pour que le rapport repasse à « À jour ».
3. Revérifier la licence amont (fichier et en-têtes). Un changement de licence
   suspend la mise à jour (label `ATTENTE LICENSE`).
4. Importer les fichiers modifiés, en gardant l'en-tête SPDX et la mention
   « Importé de… » (convention #563). Mettre à jour « Commit importé ».
   `scripts/valider_imports.py` doit passer.
5. Ouvrir une PR vers `dev`, avec `Refs #n`.

Un dépôt injoignable n'est jamais retiré automatiquement. Le README garde la
copie importée, et l'issue documente la disparition et un éventuel miroir.

## Sources http/https/ftp (étude)

Aucun dissecteur du dépôt ne vient aujourd'hui d'une source hors forge git.
Les 353 imports relevés le 04/11/2026 viennent de GitHub, GitLab et Codeberg.
Pour une telle source, `git ls-remote` est sans objet. Voici ce qui est
retenu si le cas se présente :

- **Empreinte** : noter dans le tableau « Import » une ligne
  `| Empreinte SHA-256 | `<64 hex>` |` par fichier téléchargé, en plus de
  l'URL et de la date de téléchargement.
  La comparaison se fait sur ce contenu. Les en-têtes `ETag` et `Last-Modified`
  changent sans que le fichier change (CDN, régénération), ou restent
  identiques alors qu'il a changé.
- **Version** : si l'URL est versionnée (`…/proto-1.2.lua`, archive
  `vX.Y.tar.gz`), noter la version importée et surveiller l'index de la page
  de téléchargement, pas seulement le fichier.
- **FTP** : télécharger en mode passif, avec la même empreinte. Sans TLS,
  l'intégrité ne repose que sur l'empreinte notée à l'import : une signature
  amont (`.asc`, `.sig`), quand elle existe, est vérifiée et documentée.
- **Fréquence** : les sources hors forge sont rares et peu actives.
  Une vérification à la main à chaque campagne de mise à jour suffit, au
  rythme du workflow hebdomadaire, qui les liste à part (« Hors forge git »).
- **Disparition** : copier la page source sur une archive publique
  (Software Heritage, Internet Archive) au moment de l'import, et noter le lien.

Le script se contente de lister ces sources. Le téléchargement avec contrôle
d'empreinte ne sera ajouté que si un tel import arrive, pour ne pas maintenir
du code sans cas réel.
