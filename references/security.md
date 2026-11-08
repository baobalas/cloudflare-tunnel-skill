# Security

Encryption and random hostnames do not authenticate visitors. Identify the authorized origin, audience and duration. An explicitly public non-sensitive demo permits --public; otherwise use specific allowed emails or existing app/Access authentication. Clarify missing decisions instead of choosing public access.

Sensitive cases include admin/debug consoles, private company tools/files, credentials/session data, unauthenticated writes, Docker APIs, AI endpoints and database consoles. Require effective authentication before publishing and inspect relevant routes. Never expose raw management/data services as a troubleshooting shortcut.

The helper enforces loopback HTTP(S) and an explicit exposure choice, but cannot discover every sensitive route or prove an Access assertion. Verify anonymous rejection and authorized success. A 200 login page, redirect or isolated 401 is insufficient.

Keep tokens/certificates out of chat/repositories. named-config reads only its explicitly supplied tunnel JSON, extracts TunnelID and references its private path; it never emits the secret. URL credentials/query strings are rejected. Runtime-only machines should not need account cert.pem.

State is private and outside repositories, with link/special-file checks and atomic writes. Stop requests identify the active supervisor run, never a saved PID. Same-user malicious processes and privileged attackers are outside this protection boundary.

Quick supervision bounds normal lifetime and cleans up startup failures and ordinary termination. SIGKILL of the supervisor can prevent cleanup; manually inspect the specific remaining process if this occurs. Never guess termination targets from stale PID files.

Keep TLS verification enabled; prefer a trusted CA. The explicit self-signed override only applies to loopback. Public verification respects proxy/system DNS policy and does not automatically contact DoH.

Default tests do not publish. The explicit live test exposes only a disposable synthetic page with expiry and cleanup. Reachability tests do not establish OTP, Access, webhook signatures or production suitability.
