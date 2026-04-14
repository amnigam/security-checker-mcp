# Security Checker MCP Server

Security Checker is an MCP server for AI-assisted application security review. It gives an MCP client a small, opinionated toolset for discovering files, reading code with line numbers, scanning for hardcoded secrets, searching an internal security-guideline knowledge base, and saving a final markdown report.

The server is built around a knowledge base of 150 security development guidelines across 12 domains, indexed into ChromaDB from the JSON chunks under `knowledge/chunks/`.

## What This Server Exposes

The server currently exposes:

- 5 tools
- 3 resources
- 3 prompts

### Tools

| Tool | What it does | Output |
|------|---------------|--------|
| `scan_files(target_path)` | Walks a file or directory, classifies files, and maps them to applicable security domains | JSON manifest |
| `read_file(file_path)` | Reads a file with line numbers for precise review and citation | Plain text |
| `scan_secrets(target_path)` | Runs deterministic regex-based secret detection over files | JSON findings |
| `search_guidelines(query, domain_code="", language="", top_k=5)` | Searches the guideline KB with semantic retrieval and optional filters | Formatted text |
| `save_report(content, output_path="security_report.md")` | Writes the final markdown review report to disk and prepends generation metadata | Status text |

### Resources

| Resource | What it returns |
|----------|------------------|
| `guidelines://domains` | Domain codes, names, and guideline counts |
| `guidelines://summary` | Overview of the guideline framework and available tools |
| `guidelines://{domain_code}` | All guidelines for a single domain, including text and detection hints |

### Prompts

| Prompt | Purpose |
|--------|---------|
| `security_review(target_path)` | Full 5-step directory review workflow |
| `quick_file_review(file_path)` | Single-file review with secret scan, targeted KB search, and report output |
| `secrets_audit(target_path)` | Secret-scan workflow that formats CR-05.1 findings into a reportable table |

## Review Model

This server is designed for compliance-style security review rather than generic code analysis.

- `scan_files` establishes review scope and domain coverage.
- `scan_secrets` provides a deterministic baseline for CR-05.1 violations.
- `read_file` gives the reviewer line-numbered evidence.
- `search_guidelines` supplies the actual requirement text from the KB.
- `save_report` persists the completed review in markdown.

The prompts are intentionally prescriptive. They push the reviewing agent to:

- review files in order
- search the KB with targeted queries rather than vague prompts
- report only guideline-backed findings where possible
- separate clearly exploitable unmatched issues as `UG-xxx` findings
- save the final report as a file instead of only returning chat output

## Security Domains

The knowledge base covers these 12 domains:

- `SM` Session Management
- `AU` Authentication
- `AZ` Authorization
- `IV` Input Validation and Output Encoding
- `XS` Cross-Site Scripting
- `AP` API Security
- `CR` Cryptography and Secrets
- `EL` Error Handling and Logging
- `SH` Security Headers
- `FU` File Upload Security
- `DS` Dependency and Supply Chain
- `DP` Data Protection and Privacy

All guidelines are treated as CRITICAL severity by the server and prompt workflows.

## Repository Layout

```text
src/security_checker/
  mcp_server.py           MCP server definition: tools, resources, prompts
  embedding_utils.py      Embedding backend selection
  tools/
    file_scanner.py       File discovery and classification
    file_reader.py        Line-numbered file reading
    secret_scanner.py     Regex-based secret detection
    guideline_search.py   ChromaDB-backed guideline retrieval
  scripts/
    build_kb.py           Knowledge-base builder

knowledge/
  chunks/
    guidelines_chunks.json
  chroma_store/
    ... persisted ChromaDB collection ...
```

## How the Knowledge Base Works

The project ships with guideline chunks in JSON form. The `build_kb.py` script enriches those chunks with metadata, embeds them, and writes them into a persistent ChromaDB collection named `security_guidelines`.

Embedding resolution is pragmatic:

1. `sentence-transformers` if available
2. ChromaDB's ONNX MiniLM embedding backend
3. A deterministic hash-based fallback if no embedding model is usable

That fallback keeps the server functional, but semantic search quality drops to approximate exact-term matching. If you want the best retrieval quality, install `sentence-transformers`.

## Setup

### Requirements

- Python `>=3.10,<3.14`
- `uv` recommended for local development and MCP client launch

### Install

```bash
cd security-checker-mcp
uv venv
source .venv/bin/activate
uv pip install -e .
```

### Build the Knowledge Base

The server expects the ChromaDB knowledge base to exist at startup.

```bash
python -m security_checker.scripts.build_kb --rebuild --verify
```

What this does:

- loads `knowledge/chunks/guidelines_chunks.json`
- prints a domain summary
- creates or rebuilds the `security_guidelines` Chroma collection
- optionally runs verification queries against expected guideline IDs

### Run the Server

Any of the following entry points work:

```bash
security-checker-mcp
```

```bash
uv run python -m security_checker.mcp_server
```

```bash
mcp dev src/security_checker/mcp_server.py
```

If the knowledge base has not been built, server startup fails fast with an explicit error.

## MCP Client Configuration

### VS Code

```json
{
  "servers": {
    "security-checker": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/security-checker-mcp",
        "python",
        "-m",
        "security_checker.mcp_server"
      ]
    }
  }
}
```

### Cursor

```json
{
  "mcpServers": {
    "security-checker": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/security-checker-mcp",
        "python",
        "-m",
        "security_checker.mcp_server"
      ]
    }
  }
}
```

### Claude Desktop

```json
{
  "mcpServers": {
    "security-checker": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/security-checker-mcp",
        "python",
        "-m",
        "security_checker.mcp_server"
      ]
    }
  }
}
```

## Tool Behavior and Limits

### `scan_files`

- Scans a file or directory recursively
- Skips ignored directories such as `.git`, `node_modules`, `.venv`, `dist`, `build`, and similar caches
- Skips files larger than 500 KB
- Classifies files as `source_code`, `config`, `dependency_manifest`, `ci_cd`, or `dockerfile`
- Assigns applicable guideline domains based on file type heuristics

This tool is the intended first step for a directory review.

### `read_file`

- Reads a single file with prefixed line numbers
- Rejects paths that are missing, non-files, binary, or larger than 500 KB
- Uses UTF-8 first, then falls back to Latin-1

This makes it easy for the reviewing agent to cite exact lines in the final report.

### `scan_secrets`

This scanner is deterministic and does not use an LLM. It currently includes 17 patterns covering:

- AWS access keys and secret keys
- GCP API keys and service-account key files
- Azure storage connection strings
- GitHub tokens
- Stripe keys
- Slack tokens and webhook URLs
- RSA, DSA, EC, OpenSSH, and PGP private keys
- JWTs
- password and generic secret assignments
- database connection strings with embedded credentials
- bearer tokens
- SendGrid and Twilio API keys

The returned evidence is redacted. All matches map to `CR-05.1`.

### `search_guidelines`

- Queries the ChromaDB collection with a natural-language search string
- Accepts optional `domain_code` and `language` hints
- Uses the domain filter as exact metadata matching
- Appends the language to the search query for better retrieval
- Caps `top_k` at 20 results

The output is formatted text intended for an agent to read, not structured JSON.

### `save_report`

- Writes the provided markdown report to disk
- Resolves relative output paths against the current working directory
- Creates parent directories if needed
- Prepends generation metadata comments to the file

This is the final step in the built-in review prompts.

## Prompt Workflows

### `security_review`

This is the main end-to-end workflow. It instructs the MCP client to:

1. discover files with `scan_files`
2. run `scan_secrets`
3. inspect each source and config file with `read_file`
4. search for relevant requirements with `search_guidelines`
5. synthesize and save a complete compliance report with `save_report`

It also encodes review rules such as:

- every finding should cite a guideline ID when possible
- clearly exploitable unmatched issues may be reported as `UG-xxx`
- context matters for test code vs production code

### `quick_file_review`

This prompt is optimized for a single file. It combines a line-numbered read, a secret scan, targeted KB lookup, and a required final report save.

### `secrets_audit`

This prompt is focused on secret exposure. It tells the reviewing agent to parse the JSON returned by `scan_secrets`, render findings as a table, map them all to `CR-05.1`, and provide remediation guidance based on secret type.

## Test Fixtures

The repository includes intentionally vulnerable fixtures under `tests/fixtures/` for exercising the tools and prompt workflows.

- `.env.test` contains multiple hardcoded secrets and credentials
- `nginx.conf` contains transport, CORS, and header misconfigurations
- `vulnerable_app.py` contains representative application-security violations such as weak password hashing, SQL injection, command injection, unsafe deserialization, insecure session handling, reflected XSS, and hardcoded secrets
- `package.json` is present as a dependency manifest fixture

These files are useful for testing both the tools and the agent prompts end to end.

## Current Constraints

- The knowledge base must be built before the server starts
- File scanning and reading skip files larger than 500 KB
- Secret scanning skips common binary and minified asset extensions
- Search quality depends on the embedding backend available at runtime
- File classification is heuristic rather than parser-based
- `search_guidelines` returns formatted text, so callers need to interpret the results

## Typical Usage Pattern

For a full directory review, the intended order is:

1. `scan_files`
2. `scan_secrets`
3. `read_file` for each relevant file
4. `search_guidelines` for each suspicious pattern
5. `save_report`

That flow is exactly what the built-in `security_review` prompt automates.
