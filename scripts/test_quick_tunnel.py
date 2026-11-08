#!/usr/bin/env python3
"""Offline suite by default; --live explicitly publishes only a synthetic page."""
import argparse
import functools
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/tunnel_helper.py"


def cli(*args):
    result = subprocess.run([sys.executable, str(HELPER), *args], text=True,
                            capture_output=True, timeout=45)
    try:
        data = json.loads(result.stdout)
    except ValueError:
        data = {}
    return result.returncode, data


def live_test(binary):
    with tempfile.TemporaryDirectory(prefix="cf-synthetic-live-") as temp:
        root = Path(temp).resolve()
        site = root / "site"
        site.mkdir(mode=0o700)
        expected = "SYNTHETIC-TUNNEL-TEST-" + uuid.uuid4().hex
        (site / "index.html").write_text("<!doctype html><h1>" + expected + "</h1>")
        class QuietHandler(http.server.SimpleHTTPRequestHandler):
            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), functools.partial(QuietHandler, directory=str(site)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        state = str(root / "state")
        failure = None
        report = {"kind": "synthetic-live", "public_content": "disposable test page only"}
        try:
            code, started = cli("quick", "--port", str(server.server_port), "--public",
                                "--cloudflared", binary, "--state-dir", state,
                                "--duration", "40", "--timeout", "20")
            if code:
                raise RuntimeError("live startup failed; check network and cloudflared availability")
            report["started"] = True
            verified = False
            for _ in range(4):
                code, response = cli("verify", "--url", started["public_url"],
                                     "--contains", expected, "--timeout", "5")
                if code == 0 and response.get("ok"):
                    verified = True
                    break
                time.sleep(1)
            report["expected_content_verified"] = verified
            if not verified:
                raise RuntimeError("live public content verification failed")
        except Exception as exc:
            failure = str(exc)
        finally:
            code, stopped = cli("stop", "--state-dir", state)
            state_code, status = cli("status", "--state-dir", state)
            confirmed = code == 0 and state_code == 0 and status.get("running") is False
            report["shutdown_confirmed"] = confirmed
            server.shutdown()
            server.server_close()
            thread.join()
            if not confirmed:
                failure = "live shutdown was not confirmed"
        if failure:
            report.update(ok=False, error=failure)
        else:
            report["ok"] = True
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--cloudflared")
    args = parser.parse_args()
    if not args.live:
        return subprocess.call([sys.executable, "-m", "unittest", "discover",
                                "-s", str(ROOT / "tests"), "-v"], cwd=ROOT)
    if not args.cloudflared:
        parser.error("--live requires an explicit trusted --cloudflared path")
    return live_test(str(Path(args.cloudflared).expanduser().resolve(strict=True)))


if __name__ == "__main__":
    raise SystemExit(main())
