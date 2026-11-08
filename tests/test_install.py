"""Pinned installation tests against a disposable local Git repository."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from install_skill import BUNDLE, install


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-install-")
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "repo"
        self.repo.mkdir()
        for name in BUNDLE:
            target = self.repo / name
            target.parent.mkdir(exist_ok=True, parents=True)
            target.write_bytes((ROOT / name).read_bytes())
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Local Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "-qm", "fixture")
        self.sha = self.git("rev-parse", "HEAD").decode().strip()
        self.destination = self.root / "installed"

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.PIPE)

    def test_only_reviewed_committed_files_are_installed(self):
        original = (self.repo / "SKILL.md").read_bytes()
        (self.repo / "SKILL.md").write_text("UNCOMMITTED CONTENT")
        result = install(self.repo, self.destination, self.sha)
        self.assertEqual(result["files"], len(BUNDLE))
        self.assertEqual((self.destination / "SKILL.md").read_bytes(), original)
        manifest = json.loads((self.destination / ".installation.json").read_text())
        self.assertEqual(manifest["commit"], self.sha)
        self.assertEqual(set(manifest["sha256"]), set(BUNDLE))
        self.assertTrue((self.destination / "agents/openai.yaml").is_file())

    def test_mismatched_or_unpinned_revision_rejected(self):
        for revision in ("main", "0" * 40, self.sha[:8]):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                install(self.repo, self.destination, revision)
        self.assertFalse(self.destination.exists())

    def test_existing_directory_or_link_is_never_overwritten(self):
        self.destination.mkdir(mode=0o700)
        marker = self.destination / "marker"
        marker.write_text("UNCHANGED")
        with self.assertRaises(ValueError):
            install(self.repo, self.destination, self.sha)
        self.assertEqual(marker.read_text(), "UNCHANGED")
        link = self.root / "link"
        link.symlink_to(self.destination)
        with self.assertRaises(ValueError):
            install(self.repo, link, self.sha)

    def test_tracked_symlink_is_rejected(self):
        file = self.repo / "SKILL.md"
        file.unlink()
        file.symlink_to("/tmp/untrusted")
        self.git("add", "SKILL.md")
        self.git("-c", "user.name=Local Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "-qm", "symlink fixture")
        sha = self.git("rev-parse", "HEAD").decode().strip()
        with self.assertRaises(ValueError):
            install(self.repo, self.destination, sha)
        self.assertFalse(self.destination.exists())
