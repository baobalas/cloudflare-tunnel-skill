---
name: cloudflare-tunnel
description: Use when a user wants to publish a local HTTP/HTTPS service through Cloudflare Tunnel, using a temporary preview URL or an owned fixed hostname. Determine the audience and access controls before exposure.
license: MIT
metadata:
  tags: [cloudflare, tunnel, cloudflared, localhost, public-url, preview, custom-domain]
---

# Cloudflare Tunnel

Publish only the local service and audience the user authorized. Resolve this skill's scripts/tunnel_helper.py to an absolute path. Requires Python 3.10+, trusted cloudflared, and macOS/Linux/WSL.

## Exposure decision

Identify the loopback origin, audience, duration, and sensitive routes. Publishing an origin can expose all its routes; a URL path is not a restriction.

An explicitly public, non-sensitive demo request authorizes --public. For restricted previews, use specific allowed emails or existing application authentication. Ask only for missing decisions that affect exposure; preserve authorization already given. A request for one app does not authorize other ports, private network access or account-wide changes.

Sensitive services require effective application authentication or Cloudflare Access before publication. Warnings, random URLs, an isolated 401, or an operator assertion do not establish protection. Read [security.md](references/security.md) for sensitive cases and verification boundaries.

## Modes

For temporary previews, read [quick-tunnel.md](references/quick-tunnel.md). Default lifetime is 15 minutes.

~~~bash
python3 /absolute/skill/path/scripts/tunnel_helper.py check
python3 /absolute/skill/path/scripts/tunnel_helper.py quick \
  --url http://127.0.0.1:3000 \
  --allowed-mail viewer@example.com --duration 900
~~~

Use actual authorized visitor addresses. Unsupported email authentication fails closed; never silently replace it with public exposure. Email OTP needs an interactive visitor browser and cannot serve machine-to-machine webhooks. An already authorized non-sensitive public demo may replace the email option with --public. That option does not add application authentication.

For fixed hostnames/webhooks, read [named-tunnel.md](references/named-tunnel.md). Configure Access or application authentication before DNS publication. Config generation does not create policies, DNS or a running tunnel. Use tunnel-specific JSON credentials rather than account certificates at runtime.

## Verify and finish

Public demos: use verify with --contains and expected app content. Restricted apps: verify anonymous rejection and authorized success; HTTP reachability alone is insufficient.

Return public URL, local origin, audience/authentication, expiry and the exact status/stop commands from the helper. These include an absolute --state-dir and work from another directory. Stop a demo when no longer needed.

Private state defaults outside projects under XDG_STATE_HOME or ~/.local/state, keyed by project path. Unsafe links/permissions are rejected. A running tunnel is never silently replaced; use status/stop before changing it. Legacy project PID files are ignored, and old-version processes need separate inspection.

Read [troubleshooting.md](references/troubleshooting.md) for startup, proxy, certificate and state failures. Respect proxy/system DNS policy. Do not install persistent services, change network settings, print secrets or disable authentication as implicit troubleshooting.
