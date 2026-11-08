"""Security regressions and real offline supervisor lifecycle tests."""
import argparse
import contextlib
import http.server
import importlib.util
import json
import os
import signal
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/tunnel_helper.py"
FAKE = ROOT / "tests/fixtures/fake_cloudflared.py"
spec = importlib.util.spec_from_file_location("tunnel_helper", HELPER)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        status = {"/missing": 404, "/private": 401, "/redirect": 302}.get(self.path, 200)
        self.send_response(status)
        if status == 302:
            self.send_header("Location", "/")
        self.end_headers()
        if self.path == "/slow":
            try:
                for _ in range(40):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.05)
            except (BrokenPipeError, ConnectionResetError):
                pass
            return
        self.wfile.write(b"OFFLINE TEST ONLY")
    def log_message(self, *args):
        pass


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cf-security-")
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / "state"

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, *args, env=None, cwd=None):
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        result = subprocess.run([sys.executable, str(HELPER), *args], cwd=cwd,
                                env=run_env, text=True, capture_output=True, timeout=20)
        try:
            data = json.loads(result.stdout)
        except ValueError:
            data = {}
        return result, data

    def quick(self, *args, env=None, duration=20, timeout=3):
        return self.cli("quick", "--url", self.origin, "--state-dir", str(self.state),
                        "--cloudflared", str(FAKE), "--duration", str(duration),
                        "--timeout", str(timeout), *args, env=env)

    def stop(self):
        return self.cli("stop", "--state-dir", str(self.state))

    def credentials(self):
        path = self.root / "credentials.json"
        path.write_text(json.dumps({"TunnelID": "01234567-89ab-4def-8123-456789abcdef",
                                    "TunnelSecret": "SYNTHETIC", "AccountTag": "SYNTHETIC"}))
        path.chmod(0o600)
        return path

    def test_url_option_and_scheme_injection_rejected(self):
        for value in ("-K/tmp/config", "file:///tmp/file", "ftp://127.0.0.1",
                      "http://127.0.0.1\n  - service: ssh://localhost:22",
                      "http://127.0.0.1\\evil", "http://127.0.0.1:bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                h.validate_url(value, local=True)

    def test_origin_is_loopback_only_and_has_no_secrets_or_path(self):
        for value in ("http://10.0.0.1", "http://example.com", "http://2130706433",
                      "http://user:secret@127.0.0.1", "http://127.0.0.1?key=secret",
                      "http://127.0.0.1/admin", "http://[::1%25eth0]"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                h.validate_url(value, local=True)
        self.assertEqual(h.validate_url("http://localhost:3000/", local=True), "http://127.0.0.1:3000")
        self.assertEqual(h.validate_url("https://[::1]:8443", local=True), "https://[::1]:8443")

    def test_hostnames_and_multiline_payloads_rejected(self):
        for value in ("*.example.com", "app.example.com\nother: value",
                      "127.0.0.1", "-app.example.com", "example.com:443", "app..com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                h.validate_hostname(value)

    def test_auth_decision_required_and_duration_bounded(self):
        result, _ = self.cli("quick", "--port", "3000")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.state.exists())
        for duration in ("0", "-1", "86401"):
            result, _ = self.cli("quick", "--port", "3000", "--public", "--duration", duration)
            self.assertNotEqual(result.returncode, 0)

    def test_private_state_permissions(self):
        with contextlib.closing(h.StateStore(self.state)) as store:
            store.write_json("test.json", {"ok": True})
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((self.state / "test.json").stat().st_mode), 0o600)

    def test_symlink_directory_and_ancestor_refused(self):
        real = self.root / "real"
        real.mkdir(mode=0o700)
        self.state.symlink_to(real)
        with self.assertRaises((OSError, ValueError)):
            h.StateStore(self.state)
        with self.assertRaises((OSError, ValueError)):
            h.StateStore(self.state / "nested")
        self.assertEqual(list(real.iterdir()), [])

    def test_symlink_and_hardlink_files_refused_without_overwriting(self):
        victim = self.root / "victim"
        victim.write_text("UNCHANGED")
        victim.chmod(0o600)
        with contextlib.closing(h.StateStore(self.state)) as store:
            link = self.state / "test.json"
            link.symlink_to(victim)
            for action in (lambda: store.write_json("test.json", {}),
                           lambda: store.read("test.json"), lambda: store.open_file("test.json", truncate=True)):
                with self.assertRaises((OSError, ValueError)):
                    action()
            link.unlink()
            os.link(victim, link)
            with self.assertRaises(ValueError):
                store.write_json("test.json", {})
        self.assertEqual(victim.read_text(), "UNCHANGED")

    def test_fifo_and_permissive_state_refused(self):
        with contextlib.closing(h.StateStore(self.state)) as store:
            os.mkfifo(self.state / "test.json", 0o600)
            with self.assertRaises(ValueError):
                store.read("test.json")
        self.state.chmod(0o755)
        with self.assertRaises(ValueError):
            h.StateStore(self.state)

    def test_atomic_config_creation_does_not_replace_a_racing_writer(self):
        with contextlib.closing(h.StateStore(self.state)) as store:
            barrier = threading.Barrier(2)
            original_check = store.check
            def checked_together(name):
                result = original_check(name)
                if name == "named-race.yml" and not result:
                    barrier.wait(timeout=5)
                return result
            outcomes = []
            def writer(host):
                try:
                    store.write_json("named-race.yml", {"hostname": host}, replace=False)
                    outcomes.append("created")
                except FileExistsError:
                    outcomes.append("refused")
            with patch.object(store, "check", side_effect=checked_together):
                threads = [threading.Thread(target=writer, args=(host,)) for host in ("a.example.com", "b.example.com")]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=6)
            self.assertCountEqual(outcomes, ["created", "refused"])
            self.assertIn(store.read_json("named-race.yml")["hostname"], {"a.example.com", "b.example.com"})
            self.assertEqual((self.state / "named-race.yml").stat().st_nlink, 1)

    def test_named_empty_config_survives_quick_start(self):
        credential = self.credentials()
        result, data = self.cli("named-config", "--name", "empty", "--hostname", "demo.example.com",
                                "--url", self.origin, "--credentials-file", str(credential),
                                "--state-dir", str(self.state), "--public")
        self.assertEqual(result.returncode, 0, result.stdout)
        path = Path(data["config"])
        before = path.read_bytes()
        try:
            result, _ = self.quick("--public")
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(path.read_bytes(), before)
        finally:
            self.stop()

    def test_pid_files_never_signal_unrelated_processes(self):
        with contextlib.closing(h.StateStore(self.state)) as store:
            store.write("quick.pid", str(os.getpid()).encode())
            store.write_json("quick.json", {"pid": os.getpid(), "run_id": "a" * 32})
        with patch.object(h.os, "kill") as kill, patch.object(h.os, "killpg") as killpg:
            result = h.cmd_stop(argparse.Namespace(state_dir=str(self.state)))
        self.assertFalse(result["stopped"])
        kill.assert_not_called()
        killpg.assert_not_called()

    def test_public_verify_404_401_and_redirect_are_not_success(self):
        for path, code in (("/missing", 404), ("/private", 401), ("/redirect", 302)):
            result, data = self.cli("verify", "--url", self.origin + path)
            self.assertEqual(data["status"], code)
            self.assertFalse(data["ok"])
            self.assertEqual(result.returncode, 1)
        result, data = self.cli("verify", "--url", self.origin, "--contains", "OFFLINE TEST ONLY")
        self.assertEqual(result.returncode, 0)
        result, data = self.cli("verify", "--url", self.origin + "/private", "--expect-status", "401")
        self.assertEqual(result.returncode, 0)

    def test_public_proxy_policy_and_no_implicit_doh(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://127.0.0.1:9"}):
            with patch.object(h, "build_opener") as build:
                response = build.return_value.open.return_value
                response.code = 200
                response.read1.side_effect = [b"ok", b""]
                h.fetch("https://example.com")
                self.assertFalse(any(isinstance(x, h.ProxyHandler) for x in build.call_args.args))

    def test_slow_stream_does_not_extend_verification_indefinitely(self):
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            h.fetch(self.origin + "/slow", timeout=0.2)
        self.assertLess(time.monotonic() - started, 1)

    def test_self_signed_local_tls_requires_explicit_choice(self):
        key, cert = self.root / "key.pem", self.root / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=localhost"], check=True, capture_output=True, timeout=15)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"https://127.0.0.1:{server.server_port}"
        try:
            with self.assertRaises(Exception):
                h.fetch(url, local=True)
            status, body = h.fetch(url, local=True, no_tls_verify=True)
            self.assertEqual(status, 200)
            with self.assertRaises(ValueError):
                h.fetch(url, no_tls_verify=True)
            result, data = self.cli("quick", "--url", url, "--public", "--no-tls-verify",
                                    "--state-dir", str(self.state), "--cloudflared", str(FAKE),
                                    "--duration", "10", "--timeout", "2")
            try:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                self.stop()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_named_config_is_serialized_one_route_and_not_overwritten(self):
        credential = self.credentials()
        args = ["named-config", "--name", "demo", "--hostname", "demo.example.com",
                "--url", self.origin, "--credentials-file", str(credential),
                "--state-dir", str(self.state), "--access-protected"]
        result, data = self.cli(*args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = json.loads(Path(data["config"]).read_text())
        self.assertEqual(len(config["ingress"]), 2)
        self.assertEqual(config["tunnel"], "01234567-89ab-4def-8123-456789abcdef")
        self.assertNotIn("SYNTHETIC", Path(data["config"]).read_text())
        self.assertEqual(config["ingress"][-1], {"service": "http_status:404"})
        result, _ = self.cli(*args)
        self.assertNotEqual(result.returncode, 0)

    def test_named_multiline_and_insecure_credentials_refused(self):
        credential = self.credentials()
        for key, value in (("--hostname", "demo.example.com\nbad: true"),
                           ("--url", self.origin + "\n  - service: ssh://localhost:22")):
            args = ["named-config", "--name", "demo", "--hostname", "demo.example.com",
                    "--url", self.origin, "--credentials-file", str(credential),
                    "--state-dir", str(self.state), "--public"]
            args[args.index(key) + 1] = value
            result, _ = self.cli(*args)
            self.assertNotEqual(result.returncode, 0)
        credential.chmod(0o644)
        result, _ = self.cli("named-config", "--name", "demo", "--hostname", "demo.example.com",
                             "--url", self.origin, "--credentials-file", str(credential),
                             "--state-dir", str(self.state), "--public")
        self.assertNotEqual(result.returncode, 0)

    def test_missing_email_capability_fails_closed(self):
        result, data = self.quick("--allowed-mail", "viewer@example.com", env={"FAKE_NO_EMAIL": "1"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not support", data["error"])
        self.assertFalse(self.state.exists())

    def test_start_stop_real_process_from_different_cwd(self):
        record = self.root / "process.json"
        result, data = self.quick("--allowed-mail", "viewer@example.com",
                                  env={"FAKE_RECORD": str(record), "TUNNEL_TOKEN": "SYNTHETIC"})
        try:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            process = json.loads(record.read_text())
            self.assertIn("--allowed-mail", process["args"])
            self.assertFalse(process["tunnel_env_present"])
            self.assertIn("--state-dir", data["stop_command"])
            result, status = self.cli("status", "--state-dir", str(self.state), cwd=self.root.parent)
            self.assertTrue(status["running"])
        finally:
            result, data = self.stop()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(data["stopped"])
        self.assertTrue(Path(str(record) + ".stopped").exists())
        result, data = self.stop()
        self.assertFalse(data["stopped"])

    def test_concurrent_start_is_refused_without_replacing(self):
        result, data = self.quick("--public")
        try:
            self.assertEqual(result.returncode, 0, result.stdout)
            result2, data2 = self.quick("--public")
            self.assertNotEqual(result2.returncode, 0)
            _, status = self.cli("status", "--state-dir", str(self.state))
            self.assertTrue(status["running"])
            self.assertEqual(status["run_id"], data["run_id"])
        finally:
            self.stop()

    def test_automatic_expiry_stops_real_child(self):
        record = self.root / "process.json"
        result, _ = self.quick("--public", duration=1, env={"FAKE_RECORD": str(record)})
        self.assertEqual(result.returncode, 0, result.stdout)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not Path(str(record) + ".stopped").exists():
            time.sleep(0.1)
        _, data = self.cli("status", "--state-dir", str(self.state))
        self.assertFalse(data["running"])
        self.assertEqual(data["phase"], "expired")
        self.assertTrue(Path(str(record) + ".stopped").exists())

    def test_startup_timeout_and_early_exit_leave_no_live_child(self):
        for mode in ("FAKE_SILENT", "FAKE_EARLY_EXIT"):
            with self.subTest(mode=mode):
                record = self.root / (mode + ".json")
                result, _ = self.quick("--public", timeout=1,
                                       env={mode: "1", "FAKE_RECORD": str(record)})
                self.assertNotEqual(result.returncode, 0)
                _, status = self.cli("status", "--state-dir", str(self.state))
                self.assertFalse(status["running"])

    def test_state_failure_after_launch_cleans_child(self):
        request = {"run_id": "b" * 32, "local_url": self.origin, "exposure": {"mode": "public"},
                   "cloudflared": str(FAKE), "duration": 10, "timeout": 1,
                   "protocol": "http2", "no_tls_verify": False, "ca_file": None}
        with contextlib.closing(h.StateStore(self.state)) as store:
            store.write_json("request.json", request)
            lease = store.lock("lease.lock")
            original = h.StateStore.write_json
            def failing_write(obj, name, value):
                if name == "quick.json" and value.get("phase") == "running":
                    raise OSError("injected disk error")
                return original(obj, name, value)
            args = argparse.Namespace(state_dir=str(self.state), run_id="b" * 32, lease_fd=lease)
            record = self.root / "process.json"
            with patch.dict(os.environ, {"FAKE_RECORD": str(record)}), \
                    patch.object(h.StateStore, "write_json", failing_write):
                code = h.supervisor(args)
            self.assertEqual(code, 1)
            self.assertFalse(store.running())
            self.assertTrue(Path(str(record) + ".stopped").exists())


if __name__ == "__main__":
    unittest.main()
