# Quick Tunnel

Use for an authorized short-lived demo, not production, stable callbacks, large downloads or SSE.

~~~bash
python3 /absolute/skill/path/scripts/tunnel_helper.py quick \
  --url http://127.0.0.1:3000 --allowed-mail viewer@example.com --duration 900
~~~

Repeat --allowed-mail for specific authorized visitors. Wildcard audiences are rejected. The installed binary must advertise --allowed-mail; otherwise creation stops before launch. Never silently remove authentication. Email OTP needs an interactive browser and is unsuitable for webhooks.

For an already-authorized non-sensitive public demo, replace email access with --public. This adds no application authentication. Sensitive apps need effective protection first.

Only loopback HTTP(S) origins are allowed, without paths, query strings, fragments or userinfo. Publishing an origin may expose all routes. localhost becomes 127.0.0.1; use [::1] for IPv6-only listeners.

Default maximum lifetime is 900 seconds from launch; --duration accepts 1–86400. --timeout is startup-only. Startup failure, ordinary termination, stop requests, expiry or a 1 MiB log limit clean up the real child. There is no silent retry or replacement of an active tunnel.

Use the exact returned status_command / stop_command, including absolute --state-dir, from any working directory. Unsafe state fails closed. No manual background fallback is provided because it would bypass lifecycle protections.

For public demos, verify with --contains and recognizable content. Restricted apps need anonymous rejection and authorized success. A redirect/HTTP status cannot prove OTP works. Public verification preserves proxy/system DNS policy and TLS checking.

Official behavior:
https://developers.cloudflare.com/tunnel/get-started/quick-tunnels/
