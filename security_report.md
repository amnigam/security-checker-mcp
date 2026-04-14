<!-- Security Compliance Report -->
<!-- Generated: 2026-04-14 20:13:36 UTC -->
<!-- Tool: security-checker-mcp -->

# Security Review: tests/fixtures/nginx.conf

## Summary
This file is an Nginx configuration file written in the `nginx` configuration language. I reviewed it against targeted guideline domains `CR`, `SH`, and `EL`, and also ran the deterministic secret scan.

Secret scan result: no hardcoded secrets found in `tests/fixtures/nginx.conf`.

Verdict: FAIL. The configuration violates multiple organization security guidelines covering TLS configuration, required security headers, unsafe CORS behavior, and error page handling.

## Findings
- **[CR-04.1]** line 12 — `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;` enables TLS 1.0 and TLS 1.1, which are prohibited.
  Fix: Restrict `ssl_protocols` to `TLSv1.2 TLSv1.3;` and remove legacy protocol support.

- **[SH-01.1]** line 26 — the HTTPS server block does not set a `Strict-Transport-Security` header, so HSTS is not enforced.
  Fix: Add `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;` on HTTPS responses.

- **[SH-02.1]** line 37 — responses are proxied without a `Content-Security-Policy` header.
  Fix: Add a baseline CSP such as `add_header Content-Security-Policy "default-src 'self'" always;` and tighten it for actual frontend needs.

- **[SH-03.1]** line 26 — the server does not set `X-Frame-Options`, leaving responses without clickjacking protection.
  Fix: Add `add_header X-Frame-Options SAMEORIGIN always;` or `DENY` if framing is never required.

- **[SH-04.1]** line 26 — the server does not set `X-Content-Type-Options: nosniff` on responses.
  Fix: Add `add_header X-Content-Type-Options nosniff always;`.

- **[SH-05.1]** line 37 — responses do not include a `Referrer-Policy` header.
  Fix: Add `add_header Referrer-Policy strict-origin-when-cross-origin always;` or a more restrictive policy.

- **[SH-06.1]** line 37 — responses do not include a `Permissions-Policy` header to restrict sensitive browser features.
  Fix: Add a restrictive policy such as `add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;` and only allow features explicitly required.

- **[SH-07.1]** line 49 — `/api/` sets `Access-Control-Allow-Origin *`, which is prohibited for credentialed or authenticated cross-origin API access.
  Fix: Replace `*` with an explicit allowlist of trusted origins and return the matched origin only after validation.

- **[SH-07.2]** line 48 — `/api/` sets `Access-Control-Allow-Credentials true` while also using wildcard origin at line 49.
  Fix: Never combine `Access-Control-Allow-Credentials: true` with `Access-Control-Allow-Origin: *`; validate the request `Origin`, return a specific allowed origin, and add `Vary: Origin`.

- **[EL-01.2]** line 26 — the server block does not define custom `error_page` handlers for standard HTTP error responses.
  Fix: Configure `error_page` directives for `400`, `401`, `403`, `404`, and `500`-class responses and serve generic error pages without internal details.

## Reviewed But Not Reported
- `EL-01.1` was returned during search, but `server_tokens on;` does not by itself demonstrate exposure of stack traces, SQL queries, internal paths, or framework details as required by that guideline.
- `SH-07.3` was returned during CORS search, but this file already has direct CORS violations under `SH-07.1` and `SH-07.2`; no separate preflight allowlist implementation is shown clearly enough here to support an additional distinct finding.
- Directory listing via `autoindex on;` was checked, but I did not identify a matching guideline requirement from the KB results strong enough to report as a finding.

## Domains Checked
- `CR` — weak TLS protocol configuration
- `SH` — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS
- `EL` — custom error pages and information disclosure
