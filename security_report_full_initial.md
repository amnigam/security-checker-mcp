<!-- Security Compliance Report -->
<!-- Generated: 2026-04-14 20:32:19 UTC -->
<!-- Tool: security-checker-mcp -->

# Compliance Review: tests/fixtures

## Discovery Summary
Files discovered: 4

Files by type:
- config: 2 (`.env.test`, `nginx.conf`)
- source_code: 1 (`vulnerable_app.py`)
- dependency_manifest: 1 (`package.json`)

Files and classified metadata:
- `.env.test` — type: `config`, language: `test`, applicable domains: `SH`, `CR`, `SM`, `EL`
- `package.json` — type: `dependency_manifest`, language: `json`, applicable domains: `DS`
- `nginx.conf` — type: `config`, language: `nginx`, applicable domains: `SH`, `CR`, `SM`, `EL`
- `vulnerable_app.py` — type: `source_code`, language: `python`, applicable domains: `SM`, `AU`, `AZ`, `IV`, `XS`, `AP`, `CR`, `EL`, `SH`, `FU`, `DP`

Guideline domains represented across the codebase: `AP`, `AU`, `AZ`, `CR`, `DP`, `DS`, `EL`, `FU`, `IV`, `SH`, `SM`, `XS`.

## Executive Summary
I reviewed 4 files under `tests/fixtures`, including 3 source/config files with line-by-line inspection and a deterministic secret scan across the full directory. The review found 26 CRITICAL guideline violations plus 10 hardcoded secret hits from the regex secret scan. Verdict: FAIL, because the fixture set violates requirements across `AU`, `AZ`, `CR`, `EL`, `IV`, `SH`, `SM`, and `XS`.

## Findings by Domain

### Authentication (AU)
- **[AU-01.1]** `vulnerable_app.py:20` and `vulnerable_app.py:24` — Passwords are hashed with MD5 and SHA-1, both of which are explicitly prohibited for password storage.
  Evidence: `return hashlib.md5(password.encode()).hexdigest()` and `return hashlib.sha1(password.encode()).hexdigest()`
  Fix: Replace both functions with Argon2id, bcrypt, or scrypt using a vetted password-hashing library and per-password random salts.

- **[AU-07.1]** `vulnerable_app.py:101-103` — Authentication failures distinguish between unknown usernames and wrong passwords, enabling account enumeration.
  Evidence: `return "User not found", 401` and `return "Wrong password", 401`
  Fix: Return the same generic failure response for all authentication errors, such as `Invalid username or password`, and keep detailed reasons only in protected server logs.

### Authorization (AZ)
- **[AZ-03.1]** `vulnerable_app.py:45-51` — The user profile endpoint fetches arbitrary records by sequential `user_id` without verifying that the requester is authorized to access that object.
  Evidence: `@app.route("/api/user/<int:user_id>")` and `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
  Fix: Enforce object-level authorization before the query or filter by both the authenticated principal and the target object.

### Cryptography & Secrets (CR)
- **[CR-05.1]** `.env.test:4-5,7-10,13,15,17,19,22,24-25` — Plaintext secrets are committed directly in an environment file, including database credentials, cloud keys, tokens, webhook URLs, application secrets, and passwords.
  Evidence: `DATABASE_URL=postgresql://admin:SuperSecretPass123@prod-db.example.com:5432/production`, `AWS_SECRET_ACCESS_KEY=...`, `JWT_SECRET=my-super-secret-jwt-key-that-is-way-too-simple`, `PASSWORD=admin123`
  Fix: Remove all plaintext secrets from `.env.test`; load them from an approved vault such as HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault, and inject only non-secret test placeholders into fixtures.

- **[CR-04.1]** `nginx.conf:12` — Nginx enables TLS 1.0 and TLS 1.1, which are prohibited.
  Evidence: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;`
  Fix: Restrict TLS to `TLSv1.2 TLSv1.3;` and disable all legacy protocol versions.

- **[CR-05.1]** `vulnerable_app.py:15,107-108` — Secrets are hardcoded in application code, including the Flask secret key, database credentials, and an AWS key.
  Evidence: `app.secret_key = "super_secret_key_12345"`, `DB_URL = "postgresql://admin:p@ssw0rd123@prod-db.internal:5432/maindb"`, `AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`
  Fix: Remove hardcoded secrets from source code and retrieve them at runtime from an approved secret manager or injected environment variables.

- **[CR-07.1]** `vulnerable_app.py:85` — TLS certificate validation is explicitly disabled for outbound HTTP requests.
  Evidence: `response = http_requests.get(url, verify=False)`
  Fix: Enable certificate verification, trust the system CA bundle or a managed internal CA, and fail closed on certificate errors.

### Error Handling & Logging (EL)
- **[EL-01.1]** `vulnerable_app.py:16` and `vulnerable_app.py:111` — Flask debug mode is enabled in code and at process startup, which can expose stack traces and framework details in production responses.
  Evidence: `app.config["DEBUG"] = True` and `app.run(debug=True, host="0.0.0.0")`
  Fix: Disable debug mode outside local development, load the setting from a secure environment-specific configuration source, and default production to `False`.

- **[EL-04.1]** `vulnerable_app.py:79` — The registration flow logs a plaintext password.
  Evidence: `logger.info(f"User registered: {username} with password: {password}")`
  Fix: Never log passwords or other secrets; log only a sanitized event record such as user identifier, timestamp, IP, and outcome.

- **[EL-01.2]** `nginx.conf:26` — The Nginx server block does not configure custom error pages for standard HTTP error codes.
  Evidence: the `server` block has no `error_page` directives for `400`, `401`, `403`, `404`, or `500` responses.
  Fix: Add generic custom error pages for the required status codes and ensure they do not leak internal implementation details.

### Input Validation & Output Encoding (IV)
- **[IV-05.1]** `vulnerable_app.py:31` — The username query is built with string interpolation, making it vulnerable to SQL injection.
  Evidence: `cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")`
  Fix: Use parameterized queries such as `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))`.

- **[IV-05.1]** `vulnerable_app.py:50` — The object lookup query concatenates the route parameter directly into SQL.
  Evidence: `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
  Fix: Use a parameterized query for the identifier and validate the object access separately.

- **[IV-06.1]** `vulnerable_app.py:36` — User-controlled input is executed through the shell with `shell=True`.
  Evidence: `subprocess.call(f"ping -c 1 {hostname}", shell=True)`
  Fix: Avoid shell invocation entirely and use list-based subprocess arguments, for example `subprocess.run(["ping", "-c", "1", hostname], check=True)` after strict hostname validation.

- **[IV-09.1]** `vulnerable_app.py:56-57` — Untrusted request data is deserialized with `pickle.loads`, which is an unsafe deserializer.
  Evidence: `obj = pickle.loads(data)`
  Fix: Replace pickle with a safe serialization format such as JSON and enforce strict schema validation before processing.

### Security Headers (SH)
- **[SH-01.1]** `nginx.conf:26-32` — HTTPS responses do not set `Strict-Transport-Security`.
  Evidence: the HTTPS server block configures TLS certificates but no `Strict-Transport-Security` header.
  Fix: Add `Strict-Transport-Security` with `max-age` of at least 31536000 and consider `includeSubDomains`.

- **[SH-02.1]** `nginx.conf:37-41` — Responses are proxied without a `Content-Security-Policy` header.
  Evidence: comments explicitly note `Missing: CSP` and no CSP header is configured.
  Fix: Add a baseline CSP such as `default-src 'self'` and refine it to the application’s actual resource requirements.

- **[SH-03.1]** `nginx.conf:20-21` — `X-Frame-Options` is not configured.
  Evidence: comments state `Missing X-Frame-Options` and no header is added in the server block.
  Fix: Set `X-Frame-Options` to `DENY` or `SAMEORIGIN`.

- **[SH-04.1]** `nginx.conf:23-24` — `X-Content-Type-Options: nosniff` is not configured.
  Evidence: comments state `Missing X-Content-Type-Options` and no header is added in the server block.
  Fix: Add `X-Content-Type-Options nosniff` on all responses.

- **[SH-05.1]** `nginx.conf:40-41` — Responses do not include a `Referrer-Policy` header.
  Evidence: comments explicitly note `Missing: Referrer-Policy` and no header is configured.
  Fix: Add `Referrer-Policy strict-origin-when-cross-origin` or a stricter value.

- **[SH-06.1]** `nginx.conf:40-41` — Responses do not include a `Permissions-Policy` header.
  Evidence: comments explicitly note `Missing: Permissions-Policy` and no header is configured.
  Fix: Add a restrictive `Permissions-Policy` that disables sensitive browser features unless explicitly needed.

- **[SH-07.1]** `nginx.conf:49` — The API location returns `Access-Control-Allow-Origin: *` for a credential-capable endpoint.
  Evidence: `add_header Access-Control-Allow-Origin *;`
  Fix: Validate the `Origin` header against an allowlist and return only approved origins.

- **[SH-07.2]** `nginx.conf:48-49` — The API location combines `Access-Control-Allow-Credentials: true` with a wildcard origin.
  Evidence: `add_header Access-Control-Allow-Credentials true;` and `add_header Access-Control-Allow-Origin *;`
  Fix: Never combine credentials with wildcard CORS; return a specific validated origin and add `Vary: Origin`.

### Session Management (SM)
- **[SM-01.1]** `vulnerable_app.py:41-42` — Session identifiers are generated with `random.randint`, which is not a cryptographically secure RNG.
  Evidence: `return str(random.randint(100000, 999999))`
  Fix: Generate session identifiers with a CSPRNG such as `secrets.token_urlsafe()` or the framework’s secure session mechanism.

- **[SM-04.1]** `vulnerable_app.py:67-68` — The session cookie is issued without the `Secure` attribute.
  Evidence: `resp.set_cookie("session_id", generate_session_id(), secure=False, httponly=False)`
  Fix: Set `secure=True` and ensure the application is served only over HTTPS.

- **[SM-05.1]** `vulnerable_app.py:67-68` — The session cookie is issued without the `HttpOnly` attribute.
  Evidence: `resp.set_cookie("session_id", generate_session_id(), secure=False, httponly=False)`
  Fix: Set `httponly=True` and use the framework’s hardened session-cookie defaults.

### Cross-Site Scripting (XS)
- **[XS-03.1]** `vulnerable_app.py:91-92` — User-controlled query input is reflected into HTML without output encoding.
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
- Violations found: 26
- Domains with violations: `AU`, `AZ`, `CR`, `EL`, `IV`, `SH`, `SM`, `XS`
- Clean domains: `AP`, `DP`, `DS`, `FU`

## Top 5 Priority Remediations
1. **[CR-05.1]** Remove every plaintext secret from `.env.test` and `vulnerable_app.py`, rotate exposed credentials, and move secret retrieval to an approved vault.
2. **[IV-05.1]** Replace both SQL f-string queries in `vulnerable_app.py` with parameterized queries and add tests for injection payloads.
3. **[IV-06.1]** Eliminate `shell=True` command execution and refactor the diagnostic path to use validated inputs with list-based subprocess APIs.
4. **[AU-01.1]** Replace MD5/SHA-1 password hashing with Argon2id, bcrypt, or scrypt and migrate existing hashes safely.
5. **[SH-01.1] / [SH-02.1] / [SH-03.1] / [SH-04.1] / [SH-05.1] / [SH-06.1] / [SH-07.1] / [SH-07.2]** Harden the Nginx configuration by enabling modern TLS only, adding required security headers, and replacing wildcard CORS with a validated allowlist.
