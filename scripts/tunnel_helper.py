#!/usr/bin/env python3
"""Cloudflare Tunnel helper with explicit exposure and a bounded supervisor.

Python 3.10+, macOS/Linux/WSL. No third-party Python dependencies.
State is private, outside the project. A stop request never signals a saved PID.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

if os.name == "posix":
    import fcntl

SCRIPT = Path(__file__).resolve()
MAX_FILE = 1024 * 1024
URL_PATTERN = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com(?=[/\s\"']|$)")
NAME_PATTERN = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}")
LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def clean_text(value: str) -> str:
    if not value or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("empty values, whitespace and control characters are not allowed")
    return value


def validate_url(value: str, *, local: bool = False) -> str:
    clean_text(value)
    if "\\" in value:
        raise ValueError("backslashes are not allowed in URLs")
    p = urlsplit(value)
    if p.scheme not in {"http", "https"} or not p.hostname:
        raise ValueError("URL must use http:// or https://")
    try:
        port = p.port
    except ValueError as exc:
        raise ValueError("URL has an invalid port") from exc
    if p.username is not None or p.password is not None or p.query or p.fragment:
        raise ValueError("URL credentials, query strings and fragments are not allowed")
    host = p.hostname.lower()
    if "%" in host:
        raise ValueError("encoded hosts and IPv6 scope identifiers are not allowed")
    if local:
        if p.path not in {"", "/"}:
            raise ValueError("use an origin URL; a URL path does not restrict public exposure")
        if host == "localhost":
            host = "127.0.0.1"
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("origin must be a loopback address")
        except ValueError as exc:
            raise ValueError("origin must be localhost or a literal loopback address") from exc
    else:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            validate_hostname(host)
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((p.scheme, netloc, p.path if not local else "", "", ""))


def validate_hostname(value: str) -> str:
    host = clean_text(value).lower()
    if len(host) > 253 or "." not in host or any(
        not LABEL_PATTERN.fullmatch(label) for label in host.split(".")
    ):
        raise ValueError("provide a valid hostname without wildcards, paths or ports")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("public hostname must be a DNS name")


def normalize_url(args: argparse.Namespace) -> str:
    if args.url:
        return validate_url(args.url, local=True)
    if args.port is not None and 1 <= args.port <= 65535:
        return f"http://127.0.0.1:{args.port}"
    raise ValueError("provide --url or a port between 1 and 65535")


def private_path(value: str | Path) -> Path:
    path = Path(value).expanduser().absolute()
    if ".." in path.parts or any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
        raise ValueError("unsafe filesystem path")
    return path


def open_directory(path: Path, *, create: bool = False) -> int:
    """Walk with dirfds and O_NOFOLLOW, including all ancestor components."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid not in {0, os.getuid()}:
                raise ValueError("directory ancestor is owned by another user")
            writable = stat.S_IMODE(info.st_mode) & 0o022
            if writable and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
                raise ValueError("directory ancestor is writable by other users")
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("file must be private, owned by this user, regular and not linked")


class StateStore:
    def __init__(self, path: str | Path):
        if os.name != "posix":
            raise RuntimeError("managed tunnels require macOS, Linux or WSL")
        self.path = private_path(path)
        if self.path == Path("/"):
            raise ValueError("state directory must be a private subdirectory")
        self.fd = open_directory(self.path, create=True)
        info = os.fstat(self.fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            os.close(self.fd)
            raise ValueError("state directory must be owned by this user with mode 0700")

    def close(self) -> None:
        os.close(self.fd)

    def check(self, name: str) -> bool:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
            raise ValueError("invalid state filename")
        try:
            regular(os.stat(name, dir_fd=self.fd, follow_symlinks=False))
            return True
        except FileNotFoundError:
            return False

    def open_file(self, name: str, *, truncate: bool = False, create: bool = True) -> int:
        self.check(name)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT
        fd = os.open(name, flags, 0o600, dir_fd=self.fd)
        try:
            regular(os.fstat(fd))
            if truncate:
                os.ftruncate(fd, 0)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read(self, name: str) -> str | None:
        if not self.check(name):
            return None
        fd = self.open_file(name, create=False)
        with os.fdopen(fd, "rb") as file:
            data = file.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise ValueError("state file exceeds size limit")
        return data.decode("utf-8")

    def read_json(self, name: str) -> dict:
        raw = self.read(name)
        if raw is None:
            return {}
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("state must be a JSON object")
        return value

    def write(self, name: str, data: bytes, *, replace: bool = True) -> None:
        self.check(name)
        temp = f".write-{uuid.uuid4().hex}"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(data)
                file.flush()
                os.fsync(file.fileno())
            self.check(name)
            if replace:
                os.replace(temp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
            else:
                # Atomic creation fails if another writer won the race.
                os.link(temp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd,
                        follow_symlinks=False)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temp, dir_fd=self.fd)

    def write_json(self, name: str, value: dict, *, replace: bool = True) -> None:
        self.write(name, (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode(), replace=replace)

    def unlink(self, name: str) -> None:
        if self.check(name):
            os.unlink(name, dir_fd=self.fd)

    def lock(self, name: str) -> int | None:
        fd = self.open_file(name)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            os.close(fd)
            return None

    def running(self) -> bool:
        fd = self.lock("lease.lock")
        if fd is None:
            return True
        os.close(fd)
        return False


def state_path(args: argparse.Namespace) -> Path:
    if args.state_dir:
        return private_path(args.state_dir)
    key = hashlib.sha256(str(Path.cwd().resolve()).encode()).hexdigest()[:20]
    base = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state")
    return private_path(base / "cloudflare-tunnel-skill" / key)


def environment() -> dict[str, str]:
    return {k: v for k, v in os.environ.items()
            if not k.upper().startswith(("TUNNEL_", "CLOUDFLARED_", "CF_TUNNEL_"))}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str, timeout: int = 10, *, local: bool = False,
          no_tls_verify: bool = False, ca_file: str | None = None) -> tuple[int, str]:
    url = validate_url(url, local=local)
    context = ssl.create_default_context(cafile=ca_file)
    if no_tls_verify:
        if not local:
            raise ValueError("TLS verification can only be disabled for a loopback origin")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    handlers = [NoRedirect(), HTTPSHandler(context=context)]
    if local:
        handlers.append(ProxyHandler({}))
    opener = build_opener(*handlers)
    request = Request(url, headers={"User-Agent": "cloudflare-tunnel-skill/hardened"})
    deadline = time.monotonic() + timeout
    try:
        response = opener.open(request, timeout=timeout)
    except HTTPError as exc:
        response = exc
    with response:
        data = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("HTTP response exceeded its time budget")
            chunk = response.read1(min(65536, MAX_FILE + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_FILE:
                raise ValueError("HTTP response exceeds 1 MiB limit")
        return response.code, data.decode("utf-8", errors="replace")


def require_cloudflared(args: argparse.Namespace) -> str:
    selected = args.cloudflared or shutil.which("cloudflared")
    if not selected:
        raise RuntimeError("cloudflared not found; install it from a trusted source")
    path = Path(selected).expanduser().resolve(strict=True)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        raise ValueError("cloudflared must be an executable regular file")
    if info.st_uid not in {0, os.getuid()} or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("cloudflared executable is writable by other users")
    return str(path)


def capture(command: list[str]) -> str:
    result = subprocess.run(command, env=environment(), text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=10, check=False)
    if result.returncode:
        raise RuntimeError("cloudflared capability check failed")
    return result.stdout


def exposure(args: argparse.Namespace, *, named: bool = False) -> dict:
    emails = getattr(args, "allowed_mail", None) or []
    if emails:
        for address in emails:
            clean_text(address)
            local, sep, domain = address.rpartition("@")
            if (not sep or not re.fullmatch(r"[a-zA-Z0-9.!#$%&'*+/=?^_{}|~-]+", local)
                    or local == "*"):
                raise ValueError("provide explicit allowed email addresses")
            validate_hostname(domain)
        return {"mode": "email", "allowed_mail": sorted(set(emails))}
    if getattr(args, "public", False):
        return {"mode": "public", "warning": "Anyone can reach this service unless the app authenticates them."}
    if named and getattr(args, "access_protected", False):
        return {"mode": "access", "note": "Access protection is asserted by the operator; verify it separately."}
    raise ValueError("choose email authentication or explicitly authorize public exposure")


def stop_child(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def supervisor(args: argparse.Namespace) -> int:
    store = StateStore(args.state_dir)
    proc = None
    current = {}
    stopping = False
    reason = "failed"
    previous = {}

    def on_signal(signum, frame):
        nonlocal stopping
        stopping = True

    try:
        lease_info = os.fstat(args.lease_fd)
        regular(lease_info)
        actual = os.stat("lease.lock", dir_fd=store.fd, follow_symlinks=False)
        if (lease_info.st_dev, lease_info.st_ino) != (actual.st_dev, actual.st_ino):
            raise ValueError("invalid supervisor lease")
        fcntl.flock(args.lease_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        request = store.read_json("request.json")
        if request.get("run_id") != args.run_id:
            raise ValueError("supervisor request changed")
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[sig] = signal.signal(sig, on_signal)
        origin = validate_url(request["local_url"], local=True)
        current = {"run_id": args.run_id, "phase": "starting", "local_url": origin,
                   "public_url": None, "exposure": request["exposure"],
                   "started_at": time.time(), "expires_at": time.time() + request["duration"],
                   "duration": request["duration"]}
        store.write_json("quick.json", current)
        store.write("empty.yml", b"")
        command = [request["cloudflared"], "--config", str(store.path / "empty.yml"),
                   "tunnel", "--no-autoupdate", "--protocol", request["protocol"]]
        if request["no_tls_verify"]:
            command.append("--no-tls-verify")
        if request.get("ca_file"):
            command.extend(["--origin-ca-pool", request["ca_file"]])
        for address in request["exposure"].get("allowed_mail", []):
            command.extend(["--allowed-mail", address])
        command.extend(["--url", origin])
        start = time.monotonic()
        log_fd = store.open_file("quick.log", truncate=True)
        with os.fdopen(log_fd, "w", encoding="utf-8") as log:
            proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                    env=environment(), close_fds=True)
            while True:
                if stopping or store.read_json("stop.json").get("run_id") == args.run_id:
                    reason = "stopped"
                    break
                if (time.monotonic() - start >= request["duration"]
                        or time.time() >= current["expires_at"]):
                    reason = "expired"
                    break
                if proc.poll() is not None:
                    reason = "exited"
                    break
                if os.fstat(log.fileno()).st_size > MAX_FILE:
                    raise RuntimeError("tunnel log exceeds size limit")
                if current["phase"] == "starting":
                    content = store.read("quick.log") or ""
                    match = URL_PATTERN.search(content)
                    if match and "Registered tunnel connection" in content:
                        current.update(phase="running", public_url=match.group(0))
                        store.write_json("quick.json", current)
                    elif time.monotonic() - start >= request["timeout"]:
                        raise RuntimeError("startup timed out; inspect the private quick.log")
                time.sleep(0.1)
    except Exception:
        current["error"] = "supervisor failed; inspect private logs and local configuration"
        reason = "failed"
    finally:
        if proc is not None:
            stop_child(proc)
        current["phase"] = reason
        if current.get("run_id") == args.run_id:
            with contextlib.suppress(Exception):
                store.write_json("quick.json", current)
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        store.close()
        os.close(args.lease_fd)
    return 0 if reason in {"stopped", "expired"} else 1


def hint(store: StateStore, command: str) -> str:
    return shlex.join([sys.executable, str(SCRIPT), command, "--state-dir", str(store.path)])


def request_stop(store: StateStore, run_id: str) -> None:
    store.write_json("stop.json", {"run_id": run_id})


def cmd_quick(args: argparse.Namespace) -> dict:
    origin = normalize_url(args)
    auth = exposure(args)
    binary = require_cloudflared(args)
    if auth["mode"] == "email" and "--allowed-mail" not in capture([binary, "tunnel", "--help"]):
        raise RuntimeError("this cloudflared does not support --allowed-mail; upgrade or configure app authentication")
    status, _ = fetch(origin, local=True, no_tls_verify=args.no_tls_verify, ca_file=args.ca_file)
    if not (200 <= status < 400 or status in {401, 403}):
        raise RuntimeError(f"local service returned HTTP {status}")
    store = StateStore(state_path(args))
    operation = lease = None
    worker = None
    completed = False
    run_id = uuid.uuid4().hex
    try:
        operation = store.lock("operation.lock")
        if operation is None:
            raise RuntimeError("another tunnel operation is in progress")
        lease = store.lock("lease.lock")
        if lease is None:
            raise RuntimeError("a tunnel is already active; use status/stop before changing it")
        store.unlink("stop.json")
        store.unlink("quick.json")
        request = {"run_id": run_id, "local_url": origin, "exposure": auth,
                   "cloudflared": binary, "duration": args.duration, "timeout": args.timeout,
                   "protocol": args.protocol, "no_tls_verify": args.no_tls_verify,
                   "ca_file": str(Path(args.ca_file).expanduser().resolve(strict=True)) if args.ca_file else None}
        store.write_json("request.json", request)
        fd = store.open_file("supervisor.log", truncate=True)
        with os.fdopen(fd, "w", encoding="utf-8") as log:
            worker = subprocess.Popen(
                [sys.executable, "-I", str(SCRIPT), "_supervise", "--state-dir", str(store.path),
                 "--run-id", run_id, "--lease-fd", str(lease)],
                pass_fds=(lease,), start_new_session=True, stdout=log, stderr=subprocess.STDOUT,
                env=environment(),
            )
        os.close(lease)
        lease = None
        deadline = time.monotonic() + args.timeout + 5
        while time.monotonic() < deadline:
            current = store.read_json("quick.json")
            if current.get("run_id") == run_id and current.get("phase") == "running":
                completed = True
                return {"ok": True, "mode": "quick", **current, "state_dir": str(store.path),
                        "stop_command": hint(store, "stop"), "status_command": hint(store, "status")}
            if worker.poll() is not None or current.get("phase") in {"failed", "exited", "expired", "stopped"}:
                raise RuntimeError("tunnel did not start; inspect private logs and status")
            time.sleep(0.1)
        raise RuntimeError("supervisor startup timed out")
    finally:
        if worker is not None and not completed:
            with contextlib.suppress(Exception):
                request_stop(store, run_id)
            try:
                worker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                worker.terminate()
                worker.wait(timeout=5)
        if lease is not None:
            os.close(lease)
        if operation is not None:
            os.close(operation)
        store.close()


def cmd_status(args: argparse.Namespace) -> dict:
    store = StateStore(state_path(args))
    try:
        return {"ok": True, **store.read_json("quick.json"), "running": store.running(),
                "state_dir": str(store.path), "stop_command": hint(store, "stop")}
    finally:
        store.close()


def cmd_stop(args: argparse.Namespace) -> dict:
    store = StateStore(state_path(args))
    operation = None
    try:
        operation = store.lock("operation.lock")
        if operation is None:
            raise RuntimeError("another tunnel operation is in progress")
        if not store.running():
            return {"ok": True, "stopped": False, "running": False}
        current = store.read_json("quick.json")
        run_id = current.get("run_id")
        if not isinstance(run_id, str) or not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise RuntimeError("active supervisor has no valid state; refusing to signal any saved PID")
        request_stop(store, run_id)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if not store.running():
                return {"ok": True, "stopped": True, "running": False}
            time.sleep(0.1)
        raise RuntimeError("supervisor has not confirmed shutdown; inspect private state and logs")
    finally:
        if operation is not None:
            os.close(operation)
        store.close()


def cmd_verify(args: argparse.Namespace) -> dict:
    status, body = fetch(args.url, timeout=args.timeout)
    expected = args.expect_status or list(range(200, 300))
    contains = args.contains in body if args.contains else None
    return {"ok": status in expected and contains is not False, "status": status,
            "contains": contains, "verification": "HTTP status/content only; access control needs a separate test"}


def read_credentials(path: str) -> tuple[Path, str]:
    p = private_path(path)
    parent = open_directory(p.parent)
    try:
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as file:
        regular(os.fstat(file.fileno()))
        raw = file.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise ValueError("credentials file exceeds size limit")
    try:
        value = json.loads(raw)
        tunnel_id = str(uuid.UUID(value["TunnelID"]))
        if not value.get("TunnelSecret") or not value.get("AccountTag"):
            raise ValueError()
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise ValueError("invalid tunnel credentials JSON") from exc
    return p, tunnel_id


def cmd_named_config(args: argparse.Namespace) -> dict:
    origin = normalize_url(args)
    if not NAME_PATTERN.fullmatch(args.name):
        raise ValueError("name must contain 1-63 letters/digits, underscores or hyphens")
    hostname = validate_hostname(args.hostname)
    auth = exposure(args, named=True)
    credentials, tunnel_id = read_credentials(args.credentials_file)
    config = {"tunnel": tunnel_id, "credentials-file": str(credentials),
              "ingress": [{"hostname": hostname, "service": origin}, {"service": "http_status:404"}]}
    store = StateStore(state_path(args))
    try:
        name = f"named-{args.name}.yml"
        if store.check(name):
            raise ValueError("config already exists; choose a new name instead of overwriting it")
        store.write_json(name, config, replace=False)
        path = str(store.path / name)
        return {"ok": True, "mode": "named", "config": path, "local_url": origin,
                "hostname": hostname, "exposure": auth,
                "run_command": shlex.join(["cloudflared", "tunnel", "--no-autoupdate", "--config", path, "run"]),
                "note": "Config only. Verify authentication before creating DNS or running the tunnel."}
    finally:
        store.close()


def bounded_int(low: int, high: int):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"value must be between {low} and {high}")
        return number
    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def state_options(p):
        p.add_argument("--state-dir", help="absolute private state directory; defaults outside the repo")

    def origin_options(p):
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument("--url", help="loopback HTTP/HTTPS origin, with no path or secrets")
        group.add_argument("--port", type=bounded_int(1, 65535))

    def binary_options(p):
        p.add_argument("--cloudflared", help="trusted cloudflared executable path")

    check = sub.add_parser("check", help="check cloudflared capabilities")
    binary_options(check)
    check.set_defaults(func=lambda a: {"ok": True, "version": capture([require_cloudflared(a), "--version"]).strip(),
                                      "supports_email_auth": "--allowed-mail" in capture([require_cloudflared(a), "tunnel", "--help"])})

    quick = sub.add_parser("quick", help="start an explicitly authorized tunnel with automatic expiry")
    state_options(quick)
    origin_options(quick)
    binary_options(quick)
    group = quick.add_mutually_exclusive_group(required=True)
    group.add_argument("--allowed-mail", action="append", help="allowed email; repeat for multiple visitors")
    group.add_argument("--public", action="store_true", help="explicit public demo or an app with its own authentication")
    quick.add_argument("--duration", type=bounded_int(1, 86400), default=900, help="maximum seconds from launch (default 900)")
    quick.add_argument("--timeout", type=bounded_int(1, 300), default=120, help="startup timeout, not the tunnel lifetime")
    quick.add_argument("--protocol", choices=["http2", "quic"], default="http2")
    tls = quick.add_mutually_exclusive_group()
    tls.add_argument("--no-tls-verify", action="store_true", help="explicitly trust a self-signed loopback origin")
    tls.add_argument("--ca-file", help="trusted local origin CA file")
    quick.set_defaults(func=cmd_quick)

    for name, func in (("status", cmd_status), ("stop", cmd_stop)):
        p = sub.add_parser(name)
        state_options(p)
        p.set_defaults(func=func)

    verify = sub.add_parser("verify", help="verify actual HTTP status/content without following redirects")
    verify.add_argument("--url", required=True)
    verify.add_argument("--contains")
    verify.add_argument("--expect-status", action="append", type=bounded_int(100, 599))
    verify.add_argument("--timeout", type=bounded_int(1, 120), default=20)
    verify.set_defaults(func=cmd_verify)

    named = sub.add_parser("named-config", help="generate one private config; does not publish or modify DNS")
    state_options(named)
    origin_options(named)
    named.add_argument("--name", required=True)
    named.add_argument("--hostname", required=True)
    named.add_argument("--credentials-file", required=True, help="private tunnel-specific JSON, not cert.pem")
    group = named.add_mutually_exclusive_group(required=True)
    group.add_argument("--access-protected", action="store_true", help="assert Access is already configured; verify separately")
    group.add_argument("--public", action="store_true", help="explicit public demo or independently authenticated app")
    named.set_defaults(func=cmd_named_config)

    internal = sub.add_parser("_supervise", help=argparse.SUPPRESS)
    internal.add_argument("--state-dir", required=True)
    internal.add_argument("--run-id", required=True)
    internal.add_argument("--lease-fd", required=True, type=int)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "_supervise":
        return supervisor(args)
    try:
        result = args.func(args)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("ok") else 1
    except (Exception, KeyboardInterrupt) as exc:
        message = str(exc) if isinstance(exc, (ValueError, RuntimeError)) else type(exc).__name__
        print(json.dumps({"ok": False, "error": message}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
