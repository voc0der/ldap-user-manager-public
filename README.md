# LDAP User Manager (Authelia-First Fork)

This repository is a heavily customized LDAP user/group manager with:

- Authelia header-based authentication.
- Account management with role presets and MFA orphan cleanup.
- Lease IP management UI/proxy.
- mTLS one-time-code + single-use download flow.
- Cyberpunk-themed UI variants.

This README documents the current codebase behavior in this fork.

## What This Fork Is Optimized For

- Running behind a reverse proxy/auth gateway (Authelia).
- Managing LDAP users/groups from a web UI.
- Operating a simple IP lease allowlist workflow.
- Distributing per-user mTLS client certificates with short-lived tokens.

## Important Fork Behavior

- Unauthenticated users are redirected to `/log_in/index.php`.
- `REMOTE_HTTP_HEADERS_LOGIN=true` still works for header-based auth.
- If `OIDC_ISSUER_URL` and `OIDC_CLIENT_ID` are set, OIDC login is enabled and takes precedence over header login.
- OIDC login is Authorization Code flow with PKCE and callback at `/log_in/callback.php`.
- With OIDC enabled, opening `/index.php` while unauthenticated auto-starts login (no manual button click).

## Modules and Access Model

Defined in `www/includes/modules.inc.php`.

| Module | Base Access | Extra Group Gate |
|---|---|---|
| `change_password` | Authenticated user | None |
| `account_manager` | Admin | None |
| `invite` | Authenticated user | Must be in `INVITE_ACCESS_GROUP` (default `invite`) |
| `lease_ip` | Authenticated user | Must be in `LEASE_IP_ACCESS_GROUP` (default `lease_ip`) |
| `mtls_certificate` | Authenticated user | Must be in `mtls` |
| `messages` | Authenticated user | None (entry is in the user dropdown menu) |

Notes:

- `lease_ip/index.php` also enforces `LEASE_IP_ACCESS_GROUP` membership server-side.
- `mtls_certificate/index.php` enforces `mtls` group membership server-side.
- `invite/index.php` enforces `INVITE_ACCESS_GROUP` membership server-side.
- `messages/index.php` enforces authenticated-user access server-side and is shown from the user popup menu.
- Invite creates single-group users: role/group selection is not exposed and server-side assignment is fixed to `INVITE_TARGET_GROUP` (defaults to `INVITE_ACCESS_GROUP`).
- Successful invites and Account Manager new-user creations are lineage-audit-logged to `DATA_DIR/invites/audit.json` (default `data/invites/audit.json`).

## Header Contract (from proxy)

Expected incoming headers:

- `Remote-User` -> LDAP user identity.
- `Remote-Groups` -> group list, split on `;`, `,`, or whitespace.
- `Remote-Email` -> used by mTLS/email-related flows.

Configure your proxy so clients cannot spoof these headers directly.

To harden this, set `REVERSE_PROXY_WHITELIST` to your proxy source CIDR(s).
When set, Apache only accepts requests from those source IP ranges.
Security notifications and audit events only honor forwarded client-IP headers
when the request source matches this whitelist; otherwise they record the
direct peer address.

## Quick Start (Docker)

Build image:

```bash
docker build -t lum:local .
```

Run example:

```bash
docker run --rm -p 8443:443 \
  -e REMOTE_HTTP_HEADERS_LOGIN=true \
  -e REVERSE_PROXY_WHITELIST=172.20.0.10/32 \
  -e LDAP_URI=ldap://ldap.example.internal \
  -e LDAP_BASE_DN="dc=example,dc=com" \
  -e LDAP_ADMIN_BIND_DN="cn=admin,dc=example,dc=com" \
  -e LDAP_ADMIN_BIND_PWD="change-me" \
  -e LDAP_ADMINS_GROUP=admin \
  -e TRUSTED_HOST=lum.example.com \
  -v "$PWD/data:/opt/ldap_user_manager/data" \
  -v "$PWD/ssl:/opt/ssl:ro" \
  lum:local
```

Compose-style example:

```yaml
services:
  lum:
    image: lum:local
    environment:
      REMOTE_HTTP_HEADERS_LOGIN: "true"
      REVERSE_PROXY_WHITELIST: "172.20.0.10/32"
```

## Required Environment Variables

Validated at startup in `www/includes/config.inc.php`:

- `LDAP_URI`
- `LDAP_BASE_DN`
- `LDAP_ADMIN_BIND_DN`
- `LDAP_ADMIN_BIND_PWD`
- `LDAP_ADMINS_GROUP`

## High-Value Runtime Variables

General/auth:

- `REMOTE_HTTP_HEADERS_LOGIN` (`true` recommended in this fork)
- `REVERSE_PROXY_WHITELIST` (CIDR/IP list; comma/semicolon/space-separated; only these source IPs can reach Apache)
- `REVERSE_PROXY_WHITELIST_CONF_DIR` (optional writable dir for generated Apache allowlist include; default `/tmp`)
- `HEADER_AUTH_REQUIRE_TRUSTED_PROXY` (default `true`; if `true`, header auth is denied unless source IP matches `REVERSE_PROXY_WHITELIST`)
- `TRUSTED_HOST` (recommended for safe redirects)
- `SESSION_DIR` (defaults to `data/sessions`)
- `SESSION_TIMEOUT` (minutes)
- `LUM_ALLOW_SETUP` (default `false`; set to `true` only while deliberately re-running setup after an administrator already exists)
- `NO_HTTPS` (`false` recommended in production)
- `OIDC_ISSUER_URL` (Authelia issuer URL, e.g. `https://auth.example.com`)
- `OIDC_CLIENT_ID` (OIDC client ID)
- `OIDC_CLIENT_SECRET` (OIDC client secret; optional only if your client auth method allows it)
- `OIDC_REDIRECT_URI` (optional override; default computed to `/log_in/callback.php`)
- `OIDC_DISCOVERY_URL` (optional override for discovery endpoint)
- `OIDC_SCOPES` (default: `openid profile email groups`)
- `OIDC_USERNAME_CLAIM` (default: `preferred_username`)
- `OIDC_GROUPS_CLAIM` (default: `groups`)
- `OIDC_EMAIL_CLAIM` (default: `email`)
- `OIDC_REQUIRE_LDAP_USER` (default: `true`; reject OIDC login if user cannot be mapped to LDAP)
- `OIDC_LDAP_LOOKUP_ATTRIBUTE` (default: `SITE_LOGIN_LDAP_ATTRIBUTE`; used to map OIDC user to LDAP account)
- `OIDC_LDAP_EMAIL_ATTRIBUTE` (default: `mail`; email fallback mapping attribute)
- `OIDC_END_SESSION_ENDPOINT` (optional explicit end-session URL)
- `OIDC_POST_LOGOUT_REDIRECT_URI` (optional logout return URL)
- `OIDC_HTTP_TIMEOUT` (default: `10`)
- `OIDC_TLS_SKIP_VERIFY` (`true` only for non-production testing)

When `REMOTE_HTTP_HEADERS_LOGIN=true` and `REVERSE_PROXY_WHITELIST` is unset, the UI now shows a startup security warning banner on pages rendered via `render_header()`.

LDAP behavior:

- `LDAP_USER_OU` (default `people`)
- `LDAP_GROUP_OU` (default `groups`)
- `LDAP_GROUP_MEMBERSHIP_ATTRIBUTE`
- `LDAP_GROUP_MEMBERSHIP_USES_UID`
- `FORCE_RFC2307BIS`

Mail:

- `SMTP_HOSTNAME`, `SMTP_HOST_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`
- `SMTP_USE_TLS`, `SMTP_USE_SSL`
- `EMAIL_FROM_ADDRESS`, `EMAIL_FROM_NAME`
- `NEW_MESSAGE_EMAIL_BODY` (HTML template used when a new message is sent)
- `NEW_MESSAGE_EMAIL_SUBJECT` (optional subject override)

Messages module:

- `MESSAGES_ENCRYPTION_KEY` (required; without this key the module refuses to operate)
- `MESSAGES_MAX_BODY_LENGTH` (optional; default `5000`, max `20000`)

Invite module:

- `INVITE_ACCESS_GROUP` (default `invite`; group allowed to send invites)
- `INVITE_TARGET_GROUP` (default `INVITE_ACCESS_GROUP`; group invited users are added to)

Lease IP module:

- `LEASE_IP_ACCESS_GROUP` (default `lease_ip`; group allowed to use the module)
- `LEASE_API_BASE` (upstream lease endpoint; URL or path)
- `LEASE_API_ORIGIN` (optional explicit origin for path mode)
- `VPN_CIDR` and `WG_ALLOWEDIPS` (used by connection tester UI; unset by default)

mTLS module:

- `MTLS_STAGE_BASE` (default `/mtls_stage`)
- `MTLS_SKIP_STAGE_CHECK` (defaults to skipping local pre-check)
- `MTLS_MAIL_FROM`
- `MTLS_MAIL_SENDER`
- `APPRISE_URL`
- `APPRISE_TAG` (default `all`)

Authelia/MFA orphan tooling:

- `AUTHELIA_DIR` (default `../data/authelia`)
- `ADMIN_GROUP_NAME` (default `admin`)

For the complete variable surface, inspect:

- `www/includes/config.inc.php`
- `www/account_manager/authelia_api.php`
- `www/mtls_certificate/mtls_api.php`
- `www/lease_ip/api.php`

## Data and Persistent Paths

| Path | Purpose |
|---|---|
| `/opt/ldap_user_manager/data/sessions` | Session files |
| `/opt/ldap_user_manager/data/user_preferences` | Theme preferences |
| `/opt/ldap_user_manager/data/roles/presets.json` | Role presets |
| `/opt/ldap_user_manager/data/messages/store.enc` | Encrypted messages store |
| `/opt/ldap_user_manager/data/messages/state.json` | Derived message counts/state (updated on message actions) |
| `/opt/ldap_user_manager/data/mtls/codes` | OTP records |
| `/opt/ldap_user_manager/data/mtls/tokens` | mTLS download tokens |
| `/opt/ldap_user_manager/data/mtls/logs` | mTLS audit events |
| `${AUTHELIA_DIR}` | Authelia status/actions integration files |

Persist `/opt/ldap_user_manager/data` at minimum.

### Why `data/` is blocked at the web server

`DocumentRoot` is `/opt/ldap_user_manager`, so `data/` sits *inside* the web root.
Without an explicit rule Apache serves it as static files, and
`GET /data/sessions/<sha256(username)>` returns `passkey:is_admin:timestamp` —
enough to forge an `orf_cookie` and take over any account, including an admin one.

`/etc/apache2/conf-enabled/zz-lum-hardening.conf` (generated in the `Dockerfile`)
denies HTTP access to `data/`, `includes/`, and `vendor/`. Do not remove it, and if
you add a vhost, keep it server-wide rather than per-vhost. The rule matches on
filesystem path, so it holds under any `SERVER_PATH` prefix or `Alias`.

This is an HTTP-layer rule only: PHP still reads all of these from the filesystem
normally. Staged mTLS downloads are also unaffected — they are handed to the front
proxy via `X-Accel-Redirect` to `/_protected_mtls/`, served from a separate
`/mtls_stage/` mount that is not under `DocumentRoot`.

If you would rather not rely on the web-server rule, point `SESSION_DIR` (and the
other data paths) somewhere outside `DocumentRoot` entirely.

## mTLS Flow Summary

1. User in `mtls` group opens module.
2. User requests one-time code by email.
3. User verifies code.
4. Server issues short-lived single-use token.
5. Download endpoint validates token/session/group.
6. File is served through `X-Accel-Redirect` path:
   `/_protected_mtls/<token_hash>/client.p12`

Token/code lifetimes are 5 minutes in current code.

## Security Notes

Notable controls present:

- CSRF tokens on state-changing operations in major modules.
- Session fixation mitigation (`session_regenerate_id` on login path).
- Host validation helper (`TRUSTED_HOST` preferred).
- File-size checks for avatar uploads.
- SSRF filtering in `lease_ip/test_connection.php`.

Operational requirements:

- Do not expose internal file paths for mTLS artifacts.
- Ensure proxy strips/sets auth headers.
- Keep LUM private behind the reverse proxy network. Avoid publishing container ports to untrusted networks.
- Keep `AUTHELIA_DIR` and `data` writable only by the app runtime user/group.

## Setup and Administration

- Initial LDAP structure checks/bootstrapping live under `/setup`.
- Main admin UI is `/account_manager`.
- MFA orphan cleanup UI is `/account_manager/orphans.php`.
- Lease IP UI is `/lease_ip`.
- mTLS UI is `/mtls_certificate`.

## Troubleshooting

If users get redirected to `/log_in/index.php` and fail:

- If using OIDC, confirm `OIDC_ISSUER_URL` + `OIDC_CLIENT_ID` are set and the Authelia client redirect URI matches `/log_in/callback.php` (or your `OIDC_REDIRECT_URI` override).
- If using header auth (OIDC disabled), confirm `REMOTE_HTTP_HEADERS_LOGIN=true` and that proxy sends `Remote-User`.
- Confirm the request path passes through your auth gateway.

If lease or mTLS modules are missing from nav:

- Check `Remote-Groups` contains required gates (`LEASE_IP_ACCESS_GROUP`, `mtls`).
- Admin bypass for menu gates is enabled in code, but page-level checks still apply.

If mTLS download says artifact not ready:

- Verify staging pipeline writes files to `MTLS_STAGE_BASE`.
- Verify nginx internal mapping for `/_protected_mtls/`.

If container startup fails with a reverse-proxy whitelist error:

- Validate `REVERSE_PROXY_WHITELIST` entries are valid CIDR/IP values (example: `10.0.0.5/32,10.0.1.0/24`).
- Ensure entrypoint can write `${REVERSE_PROXY_WHITELIST_CONF_DIR:-/tmp}/zz-reverse-proxy-whitelist.conf`.

## License

See `LICENSE`.
