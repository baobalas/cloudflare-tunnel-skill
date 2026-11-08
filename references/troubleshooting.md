# Troubleshooting

Check the trusted installed binary with helper check. The helper does not download/update cloudflared. Unsupported --allowed-mail must not trigger a public fallback. macOS can use trusted Homebrew packages; use Cloudflare's official instructions for other systems.

For failures, inspect private quick.log/supervisor.log in the selected --state-dir. Review identifiers/URLs before sharing logs. No unbounded retries are performed. Confirm status reports no active tunnel before intentionally retrying.

Only loopback HTTP(S) origins without paths/secrets/queries are accepted. APIs returning 404 at their root need an appropriate root response or dedicated preview frontend. Local 2xx/3xx/401/403 establish reachability, not complete authentication.

Public verification uses configured proxies/system DNS. Inspect that environment or retry later if a proxy/fake-IP resolver cannot reach a new hostname. Do not change global DNS/proxy settings implicitly.

For self-signed local HTTPS, prefer --ca-file /absolute/path/ca.pem. Explicit --no-tls-verify applies both to local preflight and the origin connection, never public verification.

Use the exact returned absolute --state-dir from another working directory. Symlinks, hard links, FIFOs, shared writable ancestors, unsafe owners and permissive state are rejected. Choose a new private location instead of changing unrelated/shared directories.

Old .cloudflare-tunnel/ PID files are ignored. Inspect old-version processes before migration; new helper cannot stop them. A stop timeout means shutdown was not confirmed and must not be reported as success.

Quick runs expire by default. Named foreground runs use Ctrl-C, without Quick expiry. For fixed-hostname issues, validate config, hostname ownership, DNS conflicts and authentication. Do not overwrite DNS, print credentials, disable Access or install a persistent service as implicit troubleshooting.

https://developers.cloudflare.com/tunnel/
