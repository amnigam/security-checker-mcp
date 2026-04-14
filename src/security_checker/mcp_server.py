"""Security Checker MCP Server.

Exposes 5 tools, 3 resources, and 3 prompts for AI-assisted
security guidelines compliance review.

Usage:
    security-checker-mcp                          # via script entry point
    uv run python -m security_checker.mcp_server  # via uv
    mcp dev src/security_checker/mcp_server.py    # via MCP Inspector
"""

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
import json
import sys

from mcp.server.fastmcp import FastMCP


# ─── Lifespan Context ─────────────────────────────────────────────

@dataclass
class AppContext:
    """Server-wide resources initialized on startup."""
    guidelines_chunks: list[dict] = field(default_factory=list)
    domain_index: dict[str, list[dict]] = field(default_factory=dict)


@asynccontextmanager
async def server_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Initialize resources on startup, verify knowledge base exists."""

    project_root = Path(__file__).resolve().parent.parent.parent
    chroma_dir = project_root / "knowledge" / "chroma_store"
    chunks_path = project_root / "knowledge" / "chunks" / "guidelines_chunks.json"

    # ── Fail fast if knowledge base hasn't been built ──
    if not chroma_dir.exists() or not any(chroma_dir.iterdir()):
        print(
            "ERROR: Knowledge base not found.\n"
            "Run: python -m security_checker.scripts.build_kb --rebuild\n",
            file=sys.stderr,
        )
        raise RuntimeError("Knowledge base not found. Build it first.")

    # ── Load guideline chunks for resources ──
    if chunks_path.exists():
        with open(chunks_path) as f:
            data = json.load(f)
        chunks = data.get("chunks", [])
    else:
        chunks = []

    # ── Build domain index for fast resource lookups ──
    domain_index: dict[str, list[dict]] = {}
    for chunk in chunks:
        domain_index.setdefault(chunk["domain_code"], []).append(chunk)

    print(f"[security-checker] Loaded {len(chunks)} guidelines across {len(domain_index)} domains", file=sys.stderr)

    yield AppContext(
        guidelines_chunks=chunks,
        domain_index=domain_index,
    )


# ─── Create Server ────────────────────────────────────────────────

mcp = FastMCP("security-checker", lifespan=server_lifespan)


# ═══════════════════════════════════════════════════════════════════
# TOOLS (5)
# ═══════════════════════════════════════════════════════════════════

@mcp.tool()
def scan_files(target_path: str) -> str:
    """Scan a directory and classify every file for security review.

    Walks the directory tree (skipping .git, node_modules, __pycache__,
    .venv, etc.) and classifies each file. Files larger than 500KB
    are skipped.

    Returns JSON with a "files" array. Each entry has:
    - path: relative file path
    - type: source_code | config | ci_cd | dependency_manifest | dockerfile
    - language: python, javascript, java, nginx, yaml, etc.
    - applicable_domains: array of guideline domain codes that apply

    Use this FIRST when starting a security review of a directory.
    The output tells you which files to examine and which guideline
    domains to search for each file.

    Args:
        target_path: Absolute path to a file or directory to scan.
    """
    from security_checker.tools.file_scanner import scan_directory
    return scan_directory(target_path)


@mcp.tool()
def read_file(file_path: str) -> str:
    """Read a file's contents with line numbers for security review.

    Returns the file content with each line prefixed by its line
    number (e.g., "  42 | def login(username, password):").
    This makes it easy to reference specific lines when reporting
    violations.

    Maximum file size: 500KB. Returns an error message for binary
    files or files exceeding the limit.

    After reading a file, examine the code for security patterns
    and use search_guidelines to retrieve the specific guidelines
    that apply to what you observe.

    Args:
        file_path: Absolute path to the file to read.
    """
    from security_checker.tools.file_reader import read_file_contents
    return read_file_contents(file_path)


@mcp.tool()
def scan_secrets(target_path: str) -> str:
    """Scan files for hardcoded secrets using 17 regex patterns.

    Detects: AWS keys, GCP keys, Azure connection strings, GitHub
    tokens, Stripe keys, Slack tokens/webhooks, RSA/DSA/EC private
    keys, JWTs, password assignments, API key assignments, database
    connection strings, bearer tokens, SendGrid/Twilio/Mailgun keys.

    Secret values are redacted in the output for safety.
    All findings map to guideline CR-05.1 (Secret Storage).

    This is a deterministic regex scan — no LLM involved, no false
    negatives for covered patterns. Run this early in any security
    review to establish a baseline of credential exposures before
    examining code logic.

    Args:
        target_path: Absolute path to a file or directory to scan.
    """
    from security_checker.tools.secret_scanner import scan_for_secrets
    return scan_for_secrets(target_path)


@mcp.tool()
def search_guidelines(
    query: str,
    domain_code: str = "",
    language: str = "",
    top_k: int = 5,
) -> str:
    """Search the organization's 150 security development guidelines.

    Performs semantic search over the guideline knowledge base.
    Returns matching guidelines with their ID, domain, full
    requirement text, and relevance score.

    The knowledge base covers 12 domains:
    SM (Session Management), AU (Authentication), AZ (Authorization),
    IV (Input Validation), XS (Cross-Site Scripting), AP (API Security),
    CR (Cryptography & Secrets), EL (Error Handling & Logging),
    SH (Security Headers), FU (File Upload), DS (Dependencies),
    DP (Data Protection).

    Tips for effective queries:
    - Use specific technical terms: "SQL injection parameterized
      queries" not "database security"
    - Combine with domain_code filter to narrow results
    - Include the programming language for language-specific patterns
    - Search for the pattern you observe, not the guideline you want

    Args:
        query: Natural language search (e.g., "password hashing MD5").
        domain_code: Optional domain filter (e.g., "AU", "IV").
        language: Optional language filter (e.g., "python").
        top_k: Number of results (default 5, max 20).
    """
    from security_checker.tools.guideline_search import search_guidelines_db
    return search_guidelines_db(query=query, domain_code=domain_code, language=language, top_k=top_k)


@mcp.tool()
def save_report(content: str, output_path: str = "security_report.md") -> str:
    """Save a security review report to a markdown file.

    Call this as the FINAL step after completing a security review.
    Pass the complete report content (markdown formatted) and an
    output file path.

    The report is saved to the specified path. If the path is
    relative, it is resolved relative to the current working
    directory. Parent directories are created if they don't exist.

    Args:
        content: The full markdown report to save.
        output_path: File path for the report (default: security_report.md).
    """
    from pathlib import Path as P
    from datetime import datetime, timezone

    try:
        out = P(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        # Prepend generation metadata
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        header = (
            f"<!-- Security Compliance Report -->\n"
            f"<!-- Generated: {timestamp} -->\n"
            f"<!-- Tool: security-checker-mcp -->\n\n"
        )

        out.write_text(header + content, encoding="utf-8")
        return f"Report saved successfully to: {out}\n({len(content)} characters, {content.count(chr(10))} lines)"
    except Exception as e:
        return f"Error saving report: {e}"


# ═══════════════════════════════════════════════════════════════════
# RESOURCES (3)
# ═══════════════════════════════════════════════════════════════════

@mcp.resource("guidelines://domains")
def list_domains() -> str:
    """Complete list of the 12 security guideline domains."""
    return (
        "Security Guideline Domains\n"
        "==========================\n\n"
        "Code | Domain                          | Guidelines\n"
        "-----|----------------------------------|----------\n"
        "SM   | Session Management               | 44\n"
        "AU   | Authentication                   | 28\n"
        "AZ   | Authorization                    | 10\n"
        "IV   | Input Validation & Output Enc.   | 19\n"
        "XS   | Cross-Site Scripting              | 5\n"
        "AP   | API Security                     | 6\n"
        "CR   | Cryptography & Secrets            | 7\n"
        "EL   | Error Handling & Logging          | 8\n"
        "SH   | Security Headers                  | 9\n"
        "FU   | File Upload Security              | 5\n"
        "DS   | Dependency & Supply Chain         | 3\n"
        "DP   | Data Protection & Privacy         | 6\n\n"
        "All 150 guidelines are severity: CRITICAL.\n"
        "Use search_guidelines with domain_code to filter by domain.\n"
    )


@mcp.resource("guidelines://summary")
def guidelines_summary() -> str:
    """Overview of the security guidelines framework and available tools."""
    return (
        "Security Guidelines Framework\n"
        "=============================\n\n"
        "This organization maintains 150 security development guidelines\n"
        "organized across 12 domains. Every guideline is CRITICAL severity.\n\n"
        "Guideline structure:\n"
        "- Each guideline has a unique ID (e.g., AU-01.1, SM-04.1)\n"
        "- IDs follow the pattern: DOMAIN_CODE-SECTION.SUB_ID\n"
        "- Full requirement text describes what code MUST or MUST NOT do\n"
        "- Detection hints list code patterns that signal violations\n"
        "- Language tags indicate which languages the guideline applies to\n\n"
        "Domains range from Authentication (28 guidelines covering password\n"
        "hashing, credential handling, JWT validation) to Session Management\n"
        "(44 guidelines covering session IDs, cookies, timeouts) to Input\n"
        "Validation (19 guidelines covering SQL injection, command injection,\n"
        "deserialization) and 9 other security areas.\n\n"
        "Available tools:\n"
        "- scan_files: discover and classify files, map to applicable domains\n"
        "- read_file: read file contents with line numbers\n"
        "- scan_secrets: regex-based detection of 17 secret patterns\n"
        "- search_guidelines: semantic search over the guideline knowledge base\n"
    )


@mcp.resource("guidelines://{domain_code}")
def domain_guidelines(domain_code: str) -> str:
    """All guidelines for a specific security domain.

    Valid domain codes: SM, AU, AZ, IV, XS, AP, CR, EL, SH, FU, DS, DP.
    """
    # Load from the chunks file directly (lifespan context not easily
    # accessible in resource handlers in all FastMCP versions)
    project_root = Path(__file__).resolve().parent.parent.parent
    chunks_path = project_root / "knowledge" / "chunks" / "guidelines_chunks.json"

    try:
        with open(chunks_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return f"Error: Guidelines chunks file not found."

    code = domain_code.upper()
    domain_chunks = [c for c in data["chunks"] if c["domain_code"] == code]

    if not domain_chunks:
        valid_codes = sorted(set(c["domain_code"] for c in data["chunks"]))
        return (
            f"No guidelines found for domain code '{code}'.\n"
            f"Valid codes: {', '.join(valid_codes)}"
        )

    domain_name = domain_chunks[0]["domain"]
    lines = [f"# {domain_name} ({code}) — {len(domain_chunks)} guidelines\n"]

    current_parent = ""
    for chunk in domain_chunks:
        if chunk["parent_code"] != current_parent:
            current_parent = chunk["parent_code"]
            lines.append(f"\n## {chunk['parent_code']} — {chunk['parent_title']}\n")
        lines.append(f"### {chunk['id']} [{chunk['severity']}]")
        lines.append(chunk["text"])
        if chunk.get("detection_hints"):
            lines.append(f"Detection patterns: {', '.join(chunk['detection_hints'])}")
        if chunk.get("applies_to"):
            lines.append(f"Languages: {', '.join(chunk['applies_to'])}")
        lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# PROMPTS (3)
# ═══════════════════════════════════════════════════════════════════

@mcp.prompt()
def security_review(target_path: str) -> str:
    """Comprehensive security review workflow for a directory.

    Guides you through a 5-step review: discovery, secret scanning,
    file-by-file code analysis, compliance report synthesis, and
    saving the report to a file.
    Uses all 5 tools: scan_files, scan_secrets, read_file,
    search_guidelines, save_report.
    """
    return f"""You are a senior application security engineer conducting a
compliance review against the organization's 150 security development
guidelines across 12 domains. All guidelines are CRITICAL severity.

TARGET: {target_path}

Execute the following 5 steps. Complete each step fully before
moving to the next. Do NOT skip steps.

═══════════════════════════════════════════════
STEP 1 — DISCOVERY
═══════════════════════════════════════════════
Call scan_files on: {target_path}

Read the returned manifest carefully. For each file, note:
- Its type (source_code, config, dependency_manifest, etc.)
- Its language
- Its applicable_domains

Summarize: how many files total, how many by type, which
guideline domains are represented across the codebase.

═══════════════════════════════════════════════
STEP 2 — SECRET SCAN
═══════════════════════════════════════════════
Call scan_secrets on: {target_path}

This is a deterministic regex scan for 17 secret patterns.
Every finding maps to guideline CR-05.1 (Secret Storage).

Record all findings. Do not dismiss any — every hardcoded
secret is a CRITICAL violation regardless of context.

═══════════════════════════════════════════════
STEP 3 — FILE-BY-FILE REVIEW
═══════════════════════════════════════════════
For each source_code and config file from the Step 1 manifest:

a) Call read_file to get the line-numbered contents.

b) Examine the code. Look for patterns like:
   - Weak hashing (md5, sha1 for passwords)
   - SQL string concatenation
   - Missing input validation or output encoding
   - Insecure cookie/session configuration
   - Missing authentication/authorization checks
   - Unsafe deserialization
   - Missing security headers
   - Debug mode enabled in production configs
   - Unpinned dependency versions
   - Sensitive data in logs or URLs

c) For each suspicious pattern, call search_guidelines
   with a targeted query. Use the file's applicable_domains
   as the domain_code filter and include the language.

   GOOD: search_guidelines("SQL injection parameterized",
                            domain_code="IV", language="python")
   BAD:  search_guidelines("security issues")

d) Read the full requirement text in the search results.
   Determine whether the code actually violates that
   specific requirement.

e) Record violations with:
   - guideline_id (e.g., AU-01.1)
   - file_path and line number(s)
   - what the code does wrong
   - the relevant code evidence
   - specific remediation

IMPORTANT: Every finding MUST reference a specific guideline ID
from the knowledge base wherever possible.

EXCEPTION — UNGUIDLINED CRITICAL FINDINGS: If you identify a
security issue that is clearly exploitable and CRITICAL in
severity, but no matching guideline exists in the knowledge base,
report it in a separate section called "Additional Critical
Findings (No Guideline Match)". For each:
- Assign a temporary ID prefixed with "UG-" (e.g., UG-001)
- Clearly state why this is critical and exploitable
- Provide the file, line, evidence, and remediation
- Note that this finding is outside the current guideline set

Do NOT use this exception for theoretical risks, best-practice
suggestions, or low-severity observations. The bar is: would a
competent attacker exploit this to compromise the application?

Context-aware judgment:
- hashlib.md5(password) → CRITICAL (AU-01.1)
- hashlib.md5(cache_key) → not a finding (non-security use)
- DEBUG=True in test settings → acceptable
- DEBUG=True in production settings → CRITICAL (EL-01.1)
- Math.random() for session IDs → CRITICAL (SM-01.1)
- Math.random() for UI animations → not a finding

═══════════════════════════════════════════════
STEP 4 — SYNTHESIS
═══════════════════════════════════════════════
Compile all findings into a compliance report:

### Executive Summary
2-3 sentences: files reviewed, findings count, pass/fail.
FAIL if any CRITICAL violations. PASS only if zero violations.

### Findings by Domain
Group under domain headers (e.g., "Authentication (AU)").
Each finding:
- **[guideline_id]** file:line — violation description
- Evidence: relevant code
- Fix: specific remediation

### Secret Scan Results
Table of all secrets from Step 2.

### Summary Statistics
- Files scanned: N
- Violations found: N
- Domains with violations: list
- Clean domains: list

### Additional Critical Findings (No Guideline Match)
If any CRITICAL issues were found that don't map to existing
guidelines, list them here with UG-xxx IDs. If none, omit
this section entirely.

### Top 5 Priority Remediations
Ranked by impact, each with guideline ID (or UG-xxx) and action.

═══════════════════════════════════════════════
STEP 5 — SAVE REPORT
═══════════════════════════════════════════════
Call save_report with the COMPLETE report you produced in
Step 4 as the content parameter.

Use output_path: "security_report.md" (or a more specific name
like "security_report_YYYY-MM-DD.md" with today's date).

Do NOT summarize or truncate — pass the full report.
Confirm the file path after saving."""


@mcp.prompt()
def quick_file_review(file_path: str) -> str:
    """Quick security review of a single file with report output."""
    return f"""Review {file_path} against the organization's security guidelines.

1. Call read_file on {file_path} to get the contents.
2. Call scan_secrets on {file_path} to check for hardcoded secrets.
3. Identify the file type and language from the contents.
4. Based on patterns you observe in the code, call search_guidelines
   with targeted queries. Use the appropriate domain_code and
   language filters.
5. For each returned guideline, check whether the code actually
   violates that requirement.

Report findings as:
- **[guideline_id]** line N — what violates the guideline
- Fix: specific remediation

Context matters:
- md5 for password hashing → CRITICAL (AU-01.1)
- md5 for cache key → not a finding
- Map every finding to a guideline ID from the KB when possible
- If you find a clearly exploitable CRITICAL issue with no matching
  guideline, report it separately with a UG-xxx ID and explain why
  it is critical. Do NOT use this for low-severity or theoretical risks.

If no violations found, confirm which domains were checked
and that the file passes review.

6. FINAL STEP: Call save_report with the complete review as the
   content parameter. Use output_path "security_report.md".
   Do NOT skip this step — the report must be saved to a file."""


@mcp.prompt()
def secrets_audit(target_path: str) -> str:
    """Scan for hardcoded secrets and report findings."""
    return f"""Run scan_secrets on {target_path}.

Parse the JSON results and present findings as a table:

| File | Line | Secret Type | Evidence |
|------|------|-------------|----------|
| ...  | ...  | ...         | ...      |

All findings violate guideline CR-05.1 (Secret Storage).

For each finding, provide a specific remediation:
- API keys → move to environment variables or a secret manager
  (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
- Private keys → store in a secure key store, never commit to VCS
- Database URLs with credentials → use environment variables,
  separate the credentials from the connection string
- Passwords → use a secrets manager, never hardcode

If no findings, confirm the scan covered N files and found
no hardcoded secrets matching the 17 detection patterns."""


# ─── Entry Point ──────────────────────────────────────────────────

def main():
    """Entry point for the 'security-checker-mcp' command."""
    mcp.run()


if __name__ == "__main__":
    main()
