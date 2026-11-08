#!/usr/bin/env python3
"""Install a reviewed local Git commit without network access or overwriting skills."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from tunnel_helper import StateStore, open_directory, private_path

BUNDLE = [
    "SKILL.md", "agents/openai.yaml", "scripts/tunnel_helper.py",
    "references/quick-tunnel.md", "references/named-tunnel.md",
    "references/security.md", "references/troubleshooting.md",
]


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=True, timeout=15)
    return result.stdout


def install(source, destination, revision):
    if not re.fullmatch(r"[0-9a-fA-F]{40}", revision):
        raise ValueError("--expected-commit must be the full reviewed 40-character Git commit")
    revision = revision.lower()
    root = Path(source).resolve(strict=True)
    if git(root, "rev-parse", "HEAD").decode().strip() != revision:
        raise ValueError("HEAD does not match the reviewed commit")
    payload = {}
    for path in BUNDLE:
        entry = git(root, "ls-tree", revision, "--", path).decode().split()
        if len(entry) < 4 or entry[0] not in {"100644", "100755"} or entry[1] != "blob":
            raise ValueError("bundle contains a missing or non-regular tracked file")
        payload[path] = git(root, "show", f"{revision}:{path}")
    destination = private_path(destination)
    if os.path.lexists(destination):
        raise ValueError("destination already exists; choose a new directory and review the previous installation")
    parent_fd = open_directory(destination.parent, create=True)
    try:
        os.mkdir(destination.name, mode=0o700, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    # All bytes come from the pinned commit, never mutable/untracked working-tree files.
    stores = {}
    try:
        stores["."] = StateStore(destination)
        for path, content in payload.items():
            parent = str(Path(path).parent)
            if parent not in stores:
                stores[parent] = StateStore(destination / parent)
            stores[parent].write(Path(path).name, content)
        stores["."].write_json(".installation.json", {
            "commit": revision,
            "sha256": {path: hashlib.sha256(content).hexdigest() for path, content in payload.items()},
        })
    finally:
        for store in stores.values():
            store.close()
    return {"ok": True, "destination": str(destination), "commit": revision, "files": len(payload)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--destination", required=True, help="new project/global skill directory")
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    try:
        result = install(args.source, args.destination, args.expected_commit)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as exc:
        message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
        print(json.dumps({"ok": False, "error": message}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
