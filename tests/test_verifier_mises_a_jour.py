# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests du suivi des mises à jour amont (scripts/verifier_mises_a_jour.py, #766).

Aucun accès réseau : ``git ls-remote`` est remplacé par une fonction de
test (paramètre ``interroger``) ou par un faux ``subprocess.run``.
"""

from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stderr, redirect_stdout

CHEMIN_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "verifier_mises_a_jour.py"
_spec = importlib.util.spec_from_file_location("verifier_mises_a_jour", CHEMIN_SCRIPT)
maj = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = maj  # requis par dataclasses à l'exécution du module
_spec.loader.exec_module(maj)

SHA_A = "a" * 40
SHA_B = "b" * 40

README = """# Proto

## Import

| | |
|---|---|
| Dépôt amont | {url} |
| Commit importé | {commit} |
| Licence amont | MIT |
"""


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.racine = pathlib.Path(self.tmp.name)
        (self.racine / "dissectors").mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def dissecteur(self, nom: str, url: str = "", commit: str = "", texte: str | None = None) -> pathlib.Path:
        rep = self.racine / "dissectors" / nom
        rep.mkdir()
        readme = rep / "README.md"
        readme.write_text(texte if texte is not None else README.format(url=url, commit=commit), encoding="utf-8")
        return readme


class LectureTests(Base):
    def test_provenance_simple(self) -> None:
        readme = self.dissecteur(
            "p", "https://github.com/o/r (`p.lua`)", f"`{SHA_A}` du 01/01/2026 (dernier commit de `main`)"
        )
        prov = maj.lire_provenance(readme)
        self.assertEqual(
            (prov.dissecteur, prov.url, prov.commit, prov.branche), ("p", "https://github.com/o/r", SHA_A, "main")
        )

    def test_depot_amont_importe_et_branches(self) -> None:
        texte = (
            "| Dépôt cité par l'issue | https://github.com/x/y |\n"
            "| Dépôt amont importé | https://codeberg.org/o/r (`Tools/a.lua`) |\n"
            f"| Commit importé | `{SHA_A}` du 05/09/2018 (dernier commit de la branche par défaut `master`) |\n"
        )
        prov = maj.lire_provenance(self.dissecteur("q", texte=texte))
        self.assertEqual((prov.url, prov.branche), ("https://codeberg.org/o/r", "master"))
        texte2 = f"| Dépôt amont | https://gitlab.com/o/r. |\n| Commit importé | `{SHA_B}` (branche `stable`) |\n"
        prov2 = maj.lire_provenance(self.dissecteur("r", texte=texte2))
        self.assertEqual((prov2.url, prov2.commit, prov2.branche), ("https://gitlab.com/o/r", SHA_B, "stable"))

    def test_provenance_absente(self) -> None:
        prov = maj.lire_provenance(self.dissecteur("vide", texte="# Rien\n"))
        self.assertEqual((prov.url, prov.commit, prov.branche), (None, None, None))
        prov2 = maj.lire_provenance(self.dissecteur("sans-url", "voir l'issue", "`court`"))
        self.assertEqual((prov2.url, prov2.commit), (None, None))


class UrlTests(unittest.TestCase):
    def test_est_git(self) -> None:
        for url in (
            "https://github.com/o/r",
            "https://www.github.com/o/r",
            "https://gitlab.com/g/s/r",
            "git://exemple.org/r",
            "https://exemple.org/r.git",
        ):
            self.assertTrue(maj.est_git(url), url)
        for url in ("https://exemple.org/proto.lua", "ftp://ftp.exemple.org/p.lua"):
            self.assertFalse(maj.est_git(url), url)

    def test_depot_git(self) -> None:
        self.assertEqual(maj.depot_git("https://github.com/o/r/tree/main/tools/"), "https://github.com/o/r")
        self.assertEqual(maj.depot_git("https://github.com/o/r/blob/main/a.lua#L3"), "https://github.com/o/r")
        self.assertEqual(maj.depot_git("https://gitlab.com/g/r/-/tree/main?x=1"), "https://gitlab.com/g/r")
        self.assertEqual(maj.depot_git("https://codeberg.org/o/r/src/branch/main"), "https://codeberg.org/o/r")


class LsRemoteTests(unittest.TestCase):
    def _run(self, **kwargs):
        return unittest.mock.patch.object(maj.subprocess, "run", **kwargs)

    def test_pointe_de_la_branche(self) -> None:
        sortie = subprocess.CompletedProcess([], 0, f"{SHA_A}\trefs/heads/main\n", "")
        with self._run(return_value=sortie) as run:
            self.assertEqual(maj.ls_remote("https://github.com/o/r", "main"), (SHA_A, ""))
        commande = run.call_args.args[0]
        self.assertEqual(commande, ["git", "ls-remote", "--", "https://github.com/o/r", "refs/heads/main"])
        self.assertEqual(run.call_args.kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")

    def test_head_et_reference_absente(self) -> None:
        with self._run(return_value=subprocess.CompletedProcess([], 0, f"{SHA_B}\tHEAD\n", "")):
            self.assertEqual(maj.ls_remote("u", None), (SHA_B, ""))
        with self._run(return_value=subprocess.CompletedProcess([], 0, "", "")):
            self.assertEqual(maj.ls_remote("u", "x"), (None, "référence refs/heads/x absente de l'amont"))

    def test_echecs(self) -> None:
        with self._run(return_value=subprocess.CompletedProcess([], 128, "", "warning\nfatal: not found\n")):
            self.assertEqual(maj.ls_remote("u", None), (None, "git ls-remote : fatal: not found"))
        with self._run(return_value=subprocess.CompletedProcess([], 2, "", "")):
            self.assertEqual(maj.ls_remote("u", None), (None, "git ls-remote : échec"))
        with self._run(side_effect=subprocess.TimeoutExpired("git", 30)):
            pointe, erreur = maj.ls_remote("u", None)
            self.assertIsNone(pointe)
            self.assertIn("timed out", erreur)
        with self._run(side_effect=FileNotFoundError("git")):
            self.assertIsNone(maj.ls_remote("u", None)[0])


def _interroger(table):
    """Fausse interrogation : ``table[(url, branche)]`` → pointe ou erreur."""

    def interroger(url, branche):
        valeur = table.get((url, branche))
        return (valeur, "") if valeur else (None, f"absent {url} {branche}")

    return interroger


class VerificationTests(Base):
    def prov(self, url="https://github.com/o/r", commit=SHA_A, branche=None):
        return maj.Provenance("p", url, commit, branche)

    def test_etats(self) -> None:
        interroger = _interroger({("https://github.com/o/r", None): SHA_A, ("https://github.com/o/r", "dev"): SHA_B})
        self.assertEqual(maj.verifier(self.prov(), interroger).etat, "a_jour")
        res = maj.verifier(self.prov(branche="dev"), interroger)
        self.assertEqual((res.etat, res.pointe), ("amont_modifie", SHA_B))
        self.assertEqual(maj.verifier(self.prov(url="https://exemple.org/p.lua"), interroger).etat, "non_git")
        absente = maj.verifier(self.prov(commit=None), interroger)
        self.assertEqual((absente.etat, absente.detail), ("provenance_absente", "manque : Commit importé"))
        res = maj.verifier(self.prov(url="https://github.com/x/y"), interroger)
        self.assertEqual((res.etat, res.detail), ("injoignable", "absent https://github.com/x/y None"))

    def test_branche_disparue_repli_sur_head(self) -> None:
        interroger = _interroger({("https://github.com/o/r", None): SHA_A})
        res = maj.verifier(self.prov(branche="ancienne"), interroger)
        self.assertEqual(res.etat, "a_jour")
        self.assertIn("branche `ancienne` absente", res.detail)
        res = maj.verifier(self.prov(url="https://github.com/x/y", branche="b"), interroger)
        self.assertEqual(res.etat, "injoignable")
        self.assertIn(" ; ", res.detail)
        meme = maj.verifier(self.prov(url="https://github.com/x/y", branche="b"), lambda u, b: (None, "panne"))
        self.assertEqual(meme.detail, "panne")

    def test_verifier_tous_et_rapport(self) -> None:
        self.dissecteur("b-modifie", "https://github.com/o/b", f"`{SHA_A}` (branche `dev`)")
        self.dissecteur("a-ajour", "https://github.com/o/a/tree/main/x", f"`{SHA_A}` (dernier commit de `main`)")
        self.dissecteur("c-http", "https://exemple.org/c.lua", f"`{SHA_A}`")
        self.dissecteur("d-vide", texte="# D\n")
        interroger = _interroger({("https://github.com/o/b", "dev"): SHA_B, ("https://github.com/o/a", "main"): SHA_A})
        resultats = maj.verifier_tous(self.racine, 2, interroger)
        self.assertEqual(
            [(r.dissecteur, r.etat) for r in resultats],
            [
                ("a-ajour", "a_jour"),
                ("b-modifie", "amont_modifie"),
                ("c-http", "non_git"),
                ("d-vide", "provenance_absente"),
            ],
        )
        texte = maj.rapport_markdown(resultats)
        self.assertIn("- Amont modifié depuis l'import : 1", texte)
        self.assertIn("- À jour : 1", texte)
        self.assertIn("| `b-modifie` | https://github.com/o/b (`dev`) | `aaaaaaaaaaaa` | `bbbbbbbbbbbb` |", texte)
        self.assertIn("## Source hors forge git", texte)
        self.assertNotIn("## Source injoignable", texte)
        self.assertNotIn("## À jour", texte)


class MainTests(Base):
    def setUp(self) -> None:
        super().setUp()
        self.dissecteur("p", "https://github.com/o/r", f"`{SHA_A}`")

    def lancer(self, *args, pointe=SHA_B):
        sortie, erreurs = io.StringIO(), io.StringIO()
        with (
            unittest.mock.patch.object(maj, "ls_remote", lambda u, b: (pointe, "")),
            redirect_stdout(sortie),
            redirect_stderr(erreurs),
        ):
            code = maj.main(["--racine", str(self.racine), *args])
        return code, sortie.getvalue(), erreurs.getvalue()

    def test_markdown_et_strict(self) -> None:
        code, sortie, erreurs = self.lancer()
        self.assertEqual(code, 0)
        self.assertIn("# Mises à jour amont des dissecteurs", sortie)
        self.assertIn("1 dissecteur(s), 1 à examiner", erreurs)
        self.assertEqual(self.lancer("--strict")[0], 1)
        self.assertEqual(self.lancer("--strict", pointe=SHA_A)[0], 0)

    def test_json_dans_un_fichier(self) -> None:
        fichier = self.racine / "rapport.json"
        code, sortie, _ = self.lancer("--json", "--sortie", str(fichier))
        self.assertEqual((code, sortie), (0, ""))
        donnees = json.loads(fichier.read_text(encoding="utf-8"))
        self.assertEqual(donnees[0]["etat"], "amont_modifie")
        self.assertEqual(donnees[0]["pointe"], SHA_B)


if __name__ == "__main__":
    unittest.main()
