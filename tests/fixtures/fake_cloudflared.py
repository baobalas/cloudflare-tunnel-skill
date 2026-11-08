#!/usr/bin/env python3
"""Offline subprocess fixture. It never opens sockets or creates a tunnel."""
import json
import os
import signal
import sys
import time
from pathlib import Path

if "--version" in sys.argv:
    print("cloudflared version offline-fixture")
    raise SystemExit()
if "--help" in sys.argv:
    if not os.environ.get("FAKE_NO_EMAIL"):
        print("--allowed-mail")
    raise SystemExit()

record = os.environ.get("FAKE_RECORD")
if record:
    Path(record).write_text(json.dumps({
        "pid": os.getpid(), "args": sys.argv[1:],
        "tunnel_env_present": any(k.startswith("TUNNEL_") for k in os.environ),
    }))
def stop(signum, frame):
    if record:
        Path(record + ".stopped").write_text("terminated")
    raise SystemExit()

signal.signal(signal.SIGTERM, stop)
if os.environ.get("FAKE_EARLY_EXIT"):
    raise SystemExit(2)
if not os.environ.get("FAKE_SILENT"):
    print("https://offline-fixture.trycloudflare.com", flush=True)
    print("Registered tunnel connection", flush=True)
while True:
    time.sleep(0.1)
