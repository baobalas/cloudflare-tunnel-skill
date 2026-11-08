# Cloudflare Tunnel Skill — Hardened Fork

Hardened baobalas fork of upstream 1f4eebaaf3baa5e1d9fb41f38cf74348f03f0ec9, MIT license retained.

[中文 / pinned installation instructions](README.md) · [Design and verification](docs/HARDENING.md)

Python 3.10+, trusted cloudflared, macOS/Linux/WSL. Native Windows process management is unsupported.

## Install and use

Review a full commit SHA, clone into a unique temporary directory, check out that exact commit and run scripts/install_skill.py with --expected-commit and --destination. See the fail-fast installation block in README.md. The installer reads only pinned regular Git blobs, includes agents/scripts/references, records SHA-256 hashes and refuses existing destinations. It never starts a tunnel. Use a new destination for upgrades.

~~~bash
python3 scripts/tunnel_helper.py check
python3 scripts/tunnel_helper.py quick \
  --url http://127.0.0.1:3000 \
  --allowed-mail viewer@example.com --duration 900
~~~

Use actual authorized visitor emails. Unsupported email authentication fails closed. Never silently fall back to public exposure. OTP requires a visitor browser and cannot protect machine-to-machine webhooks. For an explicitly authorized non-sensitive public demo, replace the email option with --public; that flag adds no authentication.

Only loopback HTTP(S) origins are accepted, without credentials, queries or paths. Publishing an origin may expose all its routes. localhost becomes 127.0.0.1; use [::1] for IPv6-only listeners. For self-signed loopback HTTPS, explicitly use --ca-file (preferred) or --no-tls-verify.

Default lifetime: 900 seconds from launch, maximum 86400. --timeout controls startup only. The supervisor handles expiry, startup failure, ordinary termination and stop requests. A 1 MiB log limit also stops the child. Concurrent starts are refused. Saved PIDs are never signalled.

Use returned absolute status/stop commands with --state-dir from other working directories. verify defaults to 2xx, follows no redirects, and supports --contains / explicit --expect-status. Restricted apps require anonymous-denial and authorized-success tests.

## Fixed hostnames

Configure Access or application authentication before DNS publication.

~~~bash
python3 scripts/tunnel_helper.py named-config \
  --name my-app --hostname app.example.com --port 3000 \
  --credentials-file /absolute/path/tunnel-uuid.json --access-protected
~~~

This only generates config. The Access flag is an operator assertion, not verification. --public explicitly allows public demos or independently authenticated apps. Credentials must be private unlinked user-owned tunnel JSON, not account cert.pem. Secrets are not copied; the config references the path and TunnelID. Serialized JSON is a YAML subset, with one origin rule and a final 404, saved privately without replacement.

Run the printed command in the foreground; Ctrl-C stops it. Named foreground runs do not use Quick expiry. See references/named-tunnel.md.

## State and tests

Private per-project state lives outside repositories under XDG_STATE_HOME or ~/.local/state. Directories are 0700 and files 0600. Unsafe links, special files, owners and shared writable ancestors are rejected. Legacy PID files are ignored; inspect/stop old-version processes before migration. Forced SIGKILL of a supervisor can prevent cleanup and requires manual inspection.

Public verification respects proxies/system DNS and retains TLS checks; no automatic DoH is used. Loopback checks bypass proxies. Child environments exclude inherited tunnel credentials/settings.

~~~bash
python3 -m unittest discover -s tests -v
python3 scripts/test_quick_tunnel.py
~~~

Default tests are offline. --live --cloudflared /trusted/path/cloudflared explicitly publishes only a disposable synthetic page, with expiry and cleanup. Offline tests do not establish real OTP, Access or business authentication. Quick Tunnels are testing-only, with uptime/concurrency/SSE limitations.
