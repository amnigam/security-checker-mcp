<!-- Security Compliance Report -->
<!-- Generated: 2026-04-14 20:54:10 UTC -->
<!-- Tool: security-checker-mcp -->

# Compliance Review: tests/fixtures

## Executive Summary
I reviewed 4 files under `tests/fixtures`, performed full manifest discovery, ran the deterministic 17-pattern secret scan, and inspected every `source_code` and `config` file line by line against targeted requirements from the organization's security guideline knowledge base. The review identified 25 CRITICAL guideline-backed violations plus 10 CRITICAL hardcoded-secret hits from the regex scan. Verdict: FAIL.

I did not report `DEBUG=True` in these files as `EL-01.1` because the reviewed files are explicitly test fixtures and your context rule states that debug mode in test settings is acceptable.

## Findings by Domain

### Authentication (AU)
- **[AU-01.1]** `tests/fixtures/vulnerable_app.py:20,24` — Passwords are hashed with MD5 and SHA-1, which are explicitly prohibited for password storage.
  Evidence: `return hashlib.md5(password.encode()).hexdigest()` and `return hashlib.sha1(password.encode()).hexdigest()`
  Fix: Replace both functions with Argon2id, bcrypt, or scrypt using a vetted password-hashing library and per-password random salts.

- **[AU-07.1]** `tests/fixtures/vulnerable_app.py:101-103` — Authentication failures distinguish between unknown users and wrong passwords, enabling account enumeration.
  Evidence: `return "User not found", 401` and `return "Wrong password", 401`
  Fix: Return the same generic failure message for all authentication failures, such as `Invalid username or password`, and keep specific reasons only in protected server logs.

### Authorization (AZ)
- **[AZ-03.1]** `tests/fixtures/vulnerable_app.py:45-51` — The user profile endpoint fetches arbitrary records by sequential `user_id` without verifying that the requester is authorized to access that object.
  Evidence: `@app.route("/api/user/<int:user_id>")` and `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
  Fix: Enforce object-level authorization before returning data, and scope the lookup to the authenticated principal or a permitted role.

### Cryptography & Secrets (CR)
- **[CR-05.1]** `tests/fixtures/.env.test:4-5,7-10,13,15,17,19,22,24-25` — Plaintext secrets are committed in an environment file, including database credentials, Redis credentials, cloud keys, JWT secrets, application secret keys, passwords, API keys, and webhook URLs.
  Evidence: `DATABASE_URL=postgresql://admin:SuperSecretPass123@prod-db.example.com:5432/production`, `REDIS_URL=redis://:redis_password_789@cache.internal:6379/0`, `JWT_SECRET=my-super-secret-jwt-key-that-is-way-too-simple`, `PASSWORD=admin123`
  Fix: Remove plaintext secrets from the fixture file, rotate any exposed real-looking credentials, and load secrets from an approved vault such as HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.

- **[CR-04.1]** `tests/fixtures/nginx.conf:12` — Nginx enables TLS 1.0 and TLS 1.1, which are prohibited.
  Evidence: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;`
  Fix: Restrict the server to `TLSv1.2 TLSv1.3;` and disable all legacy protocol versions.

- **[CR-05.1]** `tests/fixtures/vulnerable_app.py:15,107-108` — Secrets are hardcoded in application code, including the Flask secret key, a database URL with credentials, and an AWS access key.
  Evidence: `app.secret_key = "super_secret_key_12345"`, `DB_URL = "postgresql://admin:p@ssw0rd123@prod-db.internal:5432/maindb"`, `AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`
  Fix: Remove hardcoded secrets from source code and retrieve them at runtime from an approved secret manager or injected environment variables.

- **[CR-07.1]** `tests/fixtures/vulnerable_app.py:85` — Outbound HTTP requests disable TLS certificate validation.
  Evidence: `response = http_requests.get(url, verify=False)`
  Fix: Enable certificate verification, trust the proper CA bundle, and fail closed on certificate errors.

### Error Handling & Logging (EL)
- **[EL-04.1]** `tests/fixtures/vulnerable_app.py:79` — The registration flow logs a plaintext password.
  Evidence: `logger.info(f"User registered: {username} with password: {password}")`
  Fix: Never log passwords or other secrets; log only sanitized metadata such as user identifier, IP, timestamp, and outcome.

- **[EL-01.2]** `tests/fixtures/nginx.conf:26-57` — The server block does not define custom error pages for standard HTTP error responses.
  Evidence: No `error_page` directives are configured for `400`, `401`, `403`, `404`, or `500`-class responses.
  Fix: Add generic custom error pages for the required status codes and ensure they do not leak implementation details.

### Input Validation & Output Encoding (IV)
- **[IV-05.1]** `tests/fixtures/vulnerable_app.py:31` — The username lookup query is built with string interpolation.
  Evidence: `cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")`
  Fix: Use a parameterized query such as `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))`.

- **[IV-05.1]** `tests/fixtures/vulnerable_app.py:50` — The ID-based lookup query concatenates the route parameter directly into SQL.
  Evidence: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
  Fix: Use a parameterized query for the identifier and keep authorization checks separate.

- **[IV-06.1]** `tests/fixtures/vulnerable_app.py:36` — User-controlled input is executed through the shell with `shell=True`.
  Evidence: `subprocess.call(f"ping -c 1 {hostname}", shell=True)`
  Fix: Avoid shell invocation entirely and use list-based subprocess arguments after strict hostname validation.

- **[IV-09.1]** `tests/fixtures/vulnerable_app.py:56-57` — Untrusted request data is deserialized with `pickle.loads`.
  Evidence: `obj = pickle.loads(data)`
  Fix: Replace pickle with a safe format such as JSON and enforce strict schema validation before processing.

### Security Headers (SH)
- **[SH-01.1]** `tests/fixtures/nginx.conf:26-32` — HTTPS responses do not set `Strict-Transport-Security`.
  Evidence: The HTTPS server block configures certificates but no HSTS header.
  Fix: Add `Strict-Transport-Security` with `max-age` of at least `31536000`; `includeSubDomains` is recommended.

- **[SH-02.1]** `tests/fixtures/nginx.conf:37-41` — Responses are proxied without a `Content-Security-Policy` header.
  Evidence: The config notes `Missing: CSP` and no CSP header is configured.
  Fix: Add a baseline CSP such as `default-src 'self'` and refine it for actual application resource needs.

- **[SH-03.1]** `tests/fixtures/nginx.conf:20-21` — `X-Frame-Options` is not configured.
  Evidence: The config notes `Missing X-Frame-Options` and no header is added.
  Fix: Set `X-Frame-Options` to `DENY` or `SAMEORIGIN`.

- **[SH-04.1]** `tests/fixtures/nginx.conf:23-24` — `X-Content-Type-Options: nosniff` is not configured.
  Evidence: The config notes `Missing X-Content-Type-Options` and no header is added.
  Fix: Add `X-Content-Type-Options nosniff` on all responses.

- **[SH-05.1]** `tests/fixtures/nginx.conf:40-41` — Responses do not include a `Referrer-Policy` header.
  Evidence: The config notes `Missing: Referrer-Policy` and no header is configured.
  Fix: Add `Referrer-Policy strict-origin-when-cross-origin` or a stricter value.

- **[SH-06.1]** `tests/fixtures/nginx.conf:40-41` — Responses do not include a `Permissions-Policy` header.
  Evidence: The config notes `Missing: Permissions-Policy` and no header is configured.
  Fix: Add a restrictive `Permissions-Policy` that disables sensitive browser features unless explicitly needed.

- **[SH-07.1]** `tests/fixtures/nginx.conf:49` — The API location returns `Access-Control-Allow-Origin: *` for a credential-capable endpoint.
  Evidence: `add_header Access-Control-Allow-Origin *;`
  Fix: Validate the `Origin` header against an allowlist and return only approved origins.

- **[SH-07.2]** `tests/fixtures/nginx.conf:48-49` — The API location combines `Access-Control-Allow-Credentials: true` with a wildcard origin.
  Evidence: `add_header Access-Control-Allow-Credentials true;` and `add_header Access-Control-Allow-Origin *;`
  Fix: Never combine credentialed CORS with wildcard origins; return a specific validated origin and add `Vary: Origin`.

### Session Management (SM)
- **[SM-01.1]** `tests/fixtures/vulnerable_app.py:41-42` — Session identifiers are generated with `random.randint`, which is not a cryptographically secure RNG.
  Evidence: `return str(random.randint(100000, 999999))`
  Fix: Generate session IDs with a CSPRNG such as `secrets.token_urlsafe()` or rely on the framework’s secure session facilities.

- **[SM-04.1]** `tests/fixtures/vulnerable_app.py:67-68` — The session cookie is issued without the `Secure` attribute.
  Evidence: `resp.set_cookie("session_id", generate_session_id(), secure=False, httponly=False)`
  Fix: Set `secure=True` and ensure the application is served only over HTTPS.

- **[SM-05.1]** `tests/fixtures/vulnerable_app.py:67-68` — The session cookie is issued without the `HttpOnly` attribute.
  Evidence: `resp.set_cookie("session_id", generate_session_id(), secure=False, httponly=False)`
  Fix: Set `httponly=True` and use the framework’s hardened session-cookie defaults.

### Cross-Site Scripting (XS)
- **[XS-03.1]** `tests/fixtures/vulnerable_app.py:91-92` — User-controlled query input is reflected into HTML without output encoding.
  Evidence: `return f"<html><body>Results for: {query}</body></html>"`
  Fix: HTML-encode reflected input or render through a template engine that escapes by default.

## Secret Scan Results
The deterministic regex secret scan found 10 hardcoded secret matches. Every item below violates **CR-05.1**.

| File | Line | Secret Type | Evidence |
|------|------|-------------|----------|
| `.env.test` | 4 | Database Connection String | `postgresql://a***REDACTED***432/production` |
| `.env.test` | 7 | AWS Access Key ID | `AKIA***REDACTED***MPLE` |
| `.env.test` | 8 | AWS Secret Access Key | `AWS_SECRET_A***REDACTED***CYEXAMPLEKEY` |
| `.env.test` | 10 | Stripe API Key | `sk_liv***REDACTED***zdp7dc` |
| `.env.test` | 13 | GitHub Token | `ghp_ABCD***REDACTED***ghijklmn` |
| `.env.test` | 17 | Slack Webhook | `https://hooks.s***REDACTED***XXXXXXXXXXXXXXX` |
| `.env.test` | 19 | SendGrid API Key | `SG.abcdefghij***REDACTED***456789ABCDEFG` |
| `.env.test` | 25 | Secret/Token Assignment | `API_KEY="sk***REDACTED***Vault12345"` |
| `vulnerable_app.py` | 107 | Database Connection String | `postgresql:***REDACTED***5432/maindb` |
| `vulnerable_app.py` | 108 | AWS Access Key ID | `AKIA***REDACTED***MPLE` |

## Summary Statistics
- Files scanned: 4
- Files reviewed line-by-line in Step 3: 3
- Violations found: 25
- Domains with violations: `AU`, `AZ`, `CR`, `EL`, `IV`, `SH`, `SM`, `XS`
- Clean domains: `AP`, `DP`, `DS`, `FU`

## Top 5 Priority Remediations
1. **[CR-05.1]** Remove plaintext secrets from `.env.test` and `vulnerable_app.py`, rotate exposed credentials, and load secrets from an approved vault.
2. **[IV-05.1]** Replace both SQL f-string queries in `vulnerable_app.py` with parameterized queries and add tests that exercise injection payloads.
3. **[IV-06.1]** Eliminate `shell=True` command execution and refactor the diagnostic path to use validated inputs with list-based subprocess APIs.
4. **[AU-01.1]** Replace MD5 and SHA-1 password hashing with Argon2id, bcrypt, or scrypt and migrate stored hashes safely.
5. **[SH-01.1] / [SH-02.1] / [SH-03.1] / [SH-04.1] / [SH-05.1] / [SH-06.1] / [SH-07.1] / [SH-07.2]** Harden the Nginx configuration by enabling modern TLS only, adding required security headers, and replacing wildcard CORS with a validated allowlist.
