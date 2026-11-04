#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Suivi des mises à jour amont des dissecteurs importés (issue #766).

Chaque ``dissectors/<protocole>/README.md`` documente sa provenance dans le
tableau « Import » (convention #563) :

- ``| Dépôt amont | <url> … |`` (ou ``Dépôt amont importé``) ;
- ``| Commit importé | `<sha 40>` … |``, avec parfois la branche suivie
  (« dernier commit de `main` », « branche `master` »…).

Pour chaque dissecteur, le script interroge la source par
``git ls-remote`` (branche citée, sinon ``HEAD``) et compare la pointe amont
au commit importé. Il ne télécharge ni n'importe rien : une mise à jour se
fait toujours par une PR d'import (convention #563), relue par un humain.

États rapportés :

- ``a_jour`` : la pointe amont est le commit importé ;
- ``amont_modifie`` : l'amont a avancé (ou réécrit sa branche) ;
- ``injoignable`` : dépôt supprimé, renommé, privé ou réseau en échec ;
- ``non_git`` : source http/https/ftp hors forge git (voir
  ``docs/maintenance.md``, vérification manuelle) ;
- ``provenance_absente`` : tableau « Import » incomplet.

Sortie : rapport Markdown sur la sortie standard (ou ``--sortie``), JSON
avec ``--json``. Code de retour 0, sauf ``--strict`` : 1 si un amont a
bougé ou est injoignable (utile en local, pas en CI périodique).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import json
import os
import pathlib
import re
import subprocess
import sys

RACINE = pathlib.Path(__file__).resolve().parent.parent
DOSSIER_DISSECTORS = "dissectors"
# Forges git reconnues : une URL https de ces hôtes est un dépôt git.
FORGES_GIT = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org", "git.sr.ht")
DELAI_LS_REMOTE = 30  # secondes par dépôt

_LIGNE_DEPOT = re.compile(r"^\|\s*Dépôt amont(?: importé)?\s*\|(?P<cellule>.*)\|\s*$", re.MULTILINE)
_LIGNE_COMMIT = re.compile(r"^\|\s*Commit importé\s*\|(?P<cellule>.*)\|\s*$", re.MULTILINE)
_URL = re.compile(r"(?:https?|ftp|git)://[^\s|)`>]+")
_SHA = re.compile(r"`([0-9a-f]{40})`")
# « dernier commit de `main` », « branche `master` », « branche par défaut `master` »
_BRANCHE = re.compile(r"(?:branche(?: par défaut)?|commit de(?: la branche(?: par défaut)?)?)\s+`([^`]+)`")

ETATS = ("amont_modifie", "injoignable", "non_git", "provenance_absente", "a_jour")
LIBELLES = {
    "amont_modifie": "Amont modifié depuis l'import",
    "injoignable": "Source injoignable",
    "non_git": "Source hors forge git (vérification manuelle)",
    "provenance_absente": "Provenance incomplète dans le README",
    "a_jour": "À jour",
}


@dataclasses.dataclass
class Provenance:
    """Provenance d'un dissecteur, lue dans son README."""

    dissecteur: str
    url: str | None
    commit: str | None
    branche: str | None


@dataclasses.dataclass
class Resultat:
    """État d'un dissecteur après interrogation de sa source."""

    dissecteur: str
    etat: str
    url: str | None = None
    commit: str | None = None
    branche: str | None = None
    pointe: str | None = None
    detail: str = ""


def lire_provenance(readme: pathlib.Path) -> Provenance:
    """Extrait URL amont, commit importé et branche suivie du tableau « Import »."""
    texte = readme.read_text(encoding="utf-8", errors="replace")
    url = commit = branche = None
    depot = _LIGNE_DEPOT.search(texte)
    if depot:
        trouvee = _URL.search(depot.group("cellule"))
        url = trouvee.group(0).rstrip(".,;") if trouvee else None
    ligne = _LIGNE_COMMIT.search(texte)
    if ligne:
        cellule = ligne.group("cellule")
        sha = _SHA.search(cellule)
        commit = sha.group(1) if sha else None
        nom = _BRANCHE.search(cellule)
        branche = nom.group(1) if nom else None
    return Provenance(readme.parent.name, url, commit, branche)


def est_git(url: str) -> bool:
    """URL d'un dépôt git : forge connue, schéma ``git://`` ou suffixe ``.git``."""
    if url.startswith("git://") or url.endswith(".git"):
        return True
    hote = re.sub(r"^[a-z]+://([^/]+).*$", r"\1", url).lower()
    return hote in FORGES_GIT or hote.endswith(tuple("." + f for f in FORGES_GIT))


def depot_git(url: str) -> str:
    """URL du dépôt à partir d'une URL de forge (``/tree/…``, ``/blob/…`` retirés)."""
    url = url.split("#", 1)[0].split("?", 1)[0].rstrip("/")
    url = re.sub(r"/-/(?:tree|blob)/.*$", "", url)  # GitLab
    url = re.sub(r"/(?:tree|blob|src)/.*$", "", url)  # GitHub, Codeberg
    return url


def ls_remote(url: str, branche: str | None) -> tuple[str | None, str]:
    """Pointe de ``branche`` (ou ``HEAD``) du dépôt ``url`` ; ``(None, erreur)`` en échec."""
    ref = f"refs/heads/{branche}" if branche else "HEAD"
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="true")
    try:
        sortie = subprocess.run(
            ["git", "ls-remote", "--", url, ref],
            capture_output=True,
            text=True,
            timeout=DELAI_LS_REMOTE,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"git ls-remote : {exc}"
    if sortie.returncode != 0:
        erreur = (sortie.stderr.strip().splitlines() or ["échec"])[-1]
        return None, f"git ls-remote : {erreur}"
    for ligne in sortie.stdout.splitlines():
        sha, _, nom = ligne.partition("\t")
        if nom == ref:
            return sha, ""
    return None, f"référence {ref} absente de l'amont"


def verifier(provenance: Provenance, interroger=None) -> Resultat:
    """Compare la pointe amont au commit importé d'un dissecteur (``interroger`` : ``ls_remote``)."""
    interroger = interroger or ls_remote
    res = Resultat(
        provenance.dissecteur,
        "provenance_absente",
        provenance.url,
        provenance.commit,
        provenance.branche,
    )
    if not provenance.url or not provenance.commit:
        manque = [nom for nom, v in (("Dépôt amont", provenance.url), ("Commit importé", provenance.commit)) if not v]
        res.detail = "manque : " + ", ".join(manque)
        return res
    if not est_git(provenance.url):
        res.etat = "non_git"
        res.detail = "voir docs/maintenance.md (sources http/https/ftp)"
        return res
    pointe, erreur = interroger(depot_git(provenance.url), provenance.branche)
    if pointe is None and provenance.branche:
        # Branche renommée ou supprimée : on se rabat sur la branche par défaut.
        pointe, erreur_head = interroger(depot_git(provenance.url), None)
        erreur = erreur if pointe is None else f"branche `{provenance.branche}` absente, comparé à HEAD"
        if pointe is None and erreur_head != erreur:
            erreur = f"{erreur} ; {erreur_head}"
    if pointe is None:
        res.etat = "injoignable"
        res.detail = erreur
        return res
    res.pointe = pointe
    res.etat = "a_jour" if pointe == provenance.commit else "amont_modifie"
    res.detail = erreur
    return res


def lister_readmes(racine: pathlib.Path) -> list[pathlib.Path]:
    """README des dissecteurs, triés par nom de dossier."""
    return sorted((racine / DOSSIER_DISSECTORS).glob("*/README.md"))


def verifier_tous(racine: pathlib.Path, paralleles: int = 8, interroger=None) -> list[Resultat]:
    """Vérifie tous les dissecteurs (interrogations en parallèle)."""
    provenances = [lire_provenance(r) for r in lister_readmes(racine)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, paralleles)) as pool:
        return list(pool.map(lambda p: verifier(p, interroger), provenances))


def _court(sha: str | None) -> str:
    return f"`{sha[:12]}`" if sha else "—"


def rapport_markdown(resultats: list[Resultat]) -> str:
    """Rapport lisible : compteurs, puis un tableau par état à traiter."""
    par_etat: dict[str, list[Resultat]] = {e: [] for e in ETATS}
    for r in resultats:
        par_etat[r.etat].append(r)
    lignes = ["# Mises à jour amont des dissecteurs", ""]
    lignes += [f"- {LIBELLES[e]} : {len(par_etat[e])}" for e in ETATS]
    lignes.append("")
    for etat in ETATS[:-1]:
        if not par_etat[etat]:
            continue
        lignes += [
            f"## {LIBELLES[etat]}",
            "",
            "| Dissecteur | Source | Importé | Amont | Détail |",
            "|---|---|---|---|---|",
        ]
        for r in par_etat[etat]:
            source = r.url or "—"
            if r.branche:
                source += f" (`{r.branche}`)"
            lignes.append(f"| `{r.dissecteur}` | {source} | {_court(r.commit)} | {_court(r.pointe)} | {r.detail} |")
        lignes.append("")
    return "\n".join(lignes)


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée en ligne de commande."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--racine", type=pathlib.Path, default=RACINE, help="racine du dépôt")
    parser.add_argument("--json", action="store_true", help="sortie JSON au lieu du Markdown")
    parser.add_argument("--sortie", type=pathlib.Path, help="fichier du rapport (sinon sortie standard)")
    parser.add_argument("--paralleles", type=int, default=8, help="interrogations simultanées")
    parser.add_argument("--strict", action="store_true", help="code 1 si un amont a bougé ou est injoignable")
    args = parser.parse_args(argv)

    resultats = verifier_tous(args.racine, args.paralleles)
    if args.json:
        texte = json.dumps([dataclasses.asdict(r) for r in resultats], ensure_ascii=False, indent=2)
    else:
        texte = rapport_markdown(resultats)
    if args.sortie:
        args.sortie.write_text(texte + "\n", encoding="utf-8")
    else:
        print(texte)
    a_traiter = [r for r in resultats if r.etat in ("amont_modifie", "injoignable")]
    print(f"{len(resultats)} dissecteur(s), {len(a_traiter)} à examiner", file=sys.stderr)
    return 1 if args.strict and a_traiter else 0


if __name__ == "__main__":
    sys.exit(main())
