# Named Tunnel

Use an owned hostname for stable previews/webhooks. Agree on audience, origin and authentication. Specific account/DNS changes require authorization; source documents do not grant it.

Configure and test Access or application authentication before publishing DNS. For webhooks, use signature/secret validation or appropriate machine authentication. Interactive OTP is unsuitable. --access-protected asserts an operator decision; it neither creates nor verifies policies. Test anonymous denial and authorized success.

Prefer existing tunnel-specific JSON credentials. If creating a locally managed tunnel is authorized:

~~~bash
cloudflared tunnel login
cloudflared tunnel create my-app
~~~

login stores account-level cert.pem, which can manage other account tunnels. Do not copy it to runtime-only machines or print it. The tunnel UUID JSON suffices for running the specific tunnel. Remotely managed tokens should use official token-file/secret-manager mechanisms; this helper accepts locally managed JSON only.

~~~bash
python3 /absolute/skill/path/scripts/tunnel_helper.py named-config \
  --name my-app --hostname app.example.com --port 3000 \
  --credentials-file /absolute/path/tunnel-uuid.json --access-protected
~~~

The credentials file must be private, regular, owned by this user and unlinked. Public demos or independently authenticated apps can explicitly use --public.

The config references the credential path without copying secrets and uses the credential UUID. It contains one exact hostname/loopback service plus a final 404, serialized as JSON (valid YAML), privately saved without replacement.

Validate before publication:

~~~bash
cloudflared tunnel --config /absolute/private/path/my-app.yml ingress validate
~~~

Once authentication is in place and the exact DNS change is authorized:

~~~bash
cloudflared tunnel route dns TUNNEL_UUID app.example.com
~~~

Use the printed run_command in the foreground, Ctrl-C to stop. Named foreground runs have no Quick expiry. Running needs the tunnel credential, while DNS management may need the account certificate. Stopping leaves cloud definitions; do not delete them without authorization.

Official references:
- https://developers.cloudflare.com/tunnel/features/locally-managed-tunnels/configuration-file/
- https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/tunnel-permissions/
