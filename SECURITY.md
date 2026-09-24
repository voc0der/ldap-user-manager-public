# Security Policy

## Supported versions

Only the latest commit on `main` is supported. Fixes are not backported.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/voc0der/ldap-user-manager-public/security/advisories/new)
rather than opening a public issue.

Include what you can of:

- the affected file, endpoint, or module;
- steps to reproduce, or a proof of concept;
- the impact you expect (for example, which user role is needed to exploit it).

You should get an acknowledgement within a week. Once a fix is available, the
advisory is published with credit to the reporter unless you ask otherwise.

## Scope

In scope: the PHP application under `www/`, the `Dockerfile`, and the
`entrypoint` script.

Out of scope: vulnerabilities in the external services this project integrates
with (Authelia, CrowdSec, Apprise, the LDAP server, the reverse proxy), and
deployments that ignore the hardening guidance in `README.md` (for example,
exposing the container directly without a trusted reverse proxy).
