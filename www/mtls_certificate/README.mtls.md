# mTLS Certificate module

This module adds a secure, single-use, short-lived download flow for per-user mTLS client certificates behind Authelia.

## Requirements

- Authelia in front of this path, providing headers:
  - `Remote-User` (uid), `Remote-Email` (optional), `Remote-Groups` containing `mtls`
- Nginx with `X-Accel-Redirect` mapping for an **internal** path.
- An external stager process (not part of this repository) that watches `data/mtls/tokens/`, builds the token-scoped artifact under `MTLS_STAGE_BASE/<token_hash>/` for whatever export type was requested, and writes back to the token record (`artifact_ready`, `expires_days`, and `p12_pass_b64` for PKCS#12 exports):
  - PKCS#12 export: `client.p12`
  - CRT/KEY ZIP export: `cert-key.zip` containing `cert.crt` and `privkey.pem`
  - All bundle export: `all-certs.zip` with location folders, certs, and password files
- For `location=internal` (admins only), the stager is responsible for sourcing the internal certificate material; it may take longer to become ready, so the UI polls for up to 2 minutes (inside the token's 5-minute expiry).

## Environment variables

- `APPRISE_URL`   : Apprise endpoint (used via `curl -X POST --form-string 'body=...'`)
- `MTLS_MAIL_FROM`: From address for the email one-time code (PHP `mail()`)
- `MTLS_MAIL_SENDER`: Optional SMTP sender/return-path override
- `MTLS_STAGE_BASE`: Staging root mounted read-only in the app container (default `/mtls_stage`)
- `MTLS_SKIP_STAGE_CHECK`: If `false`, download endpoint checks local stage file before issuing `X-Accel-Redirect`

## Export modes

- Default export: `.pfx` (`client.p12`) with PKCS#12 password support.
- Optional export: `.zip` (`cert-key.zip`) containing:
  - `cert.crt`
  - `privkey.pem`
- Optional export: `All` bundle `.zip` (`all-certs.zip`) containing a folder hierarchy:
  - `external/pfx/` + `external/crt_key/`
  - `internal/pfx/` + `internal/crt_key/` (admins only)
  - `pkcs12.pass` files included in each location folder when available

## UI flow

- Step 1: `Customize`
  - `Location` (admins only): external/internal
  - `Export type` (all mtls users): `.pfx` (default), CRT/KEY ZIP, or All bundle ZIP
- Step 2: Send code
- Step 3: Verify
- Step 4: Download

### Deep links

Step 1 can be preselected via query string; a valid combination auto-clicks `Continue` and lands on step 2 (invalid values are ignored):

- `?type=export&target=pfx` → `.pfx`
- `?type=export&target=zip` → CRT/KEY ZIP
- `?type=export&target=allzip` → All bundle ZIP

Location is not part of the link; admins get their current session location.

With a valid link, step 1's options are collapsed. In their place is a "You're here to download …" toast, which fades out after ~9 seconds or can be closed, plus short per-target instructions that stay. A "Choose a different download" link returns to the full options. If saving the preset fails, the options are shown again so the user can retry.

## Nginx example

```
# Public app location (proxied to PHP app)
location /mtls_certificate/ {
    # ... your usual proxy_* and Authelia auth here ...
    proxy_set_header Remote-User   $upstream_http_remote_user;
    proxy_set_header Remote-Email  $upstream_http_remote_email;
    proxy_set_header Remote-Groups $upstream_http_remote_groups;
}

# Internal protected files (never directly exposed)
location /_protected_mtls/ {
    internal;
    # Map opaque to real path with alias/resolver or a Lua map.
    # Simple alias example (requires deterministic file names):
    # alias /mnt/mtls-certs/;
    # More secure approach: use a small Lua or subrequest to translate sha1 to path.
}
```

## Notes

- The email code is hashed (password_hash) and expires in 5 minutes.
- Download token is single-use, session-bound, and expires in 5 minutes.
- All user/path resolution is server-side based on the authenticated uid.
- Non-admin users are forced to `external` location on the backend.
