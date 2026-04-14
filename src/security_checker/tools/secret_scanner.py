"""SecretScanner — regex-based detection of hardcoded secrets (17 patterns).

Deterministic detector that requires no LLM. Scans files for AWS keys,
GCP keys, Azure strings, GitHub/Stripe/Slack tokens, private keys, JWTs,
database URLs, passwords, and more. Redacts evidence in output.
"""

import json
import os
import re
from pathlib import Path

SECRET_PATTERNS = [
    {"name": "AWS Access Key ID", "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
     "description": "AWS Access Key ID found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "AWS Secret Access Key", "pattern": r"(?i)aws_?secret_?access_?key[\s]*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
     "description": "AWS Secret Access Key found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "GCP API Key", "pattern": r"AIza[0-9A-Za-z\-_]{35}",
     "description": "Google Cloud API key found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "GCP Service Account", "pattern": r"\"type\":\s*\"service_account\"",
     "description": "GCP service account JSON key file detected", "guideline_id": "CR-05.1"},
    {"name": "Azure Connection String", "pattern": r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+",
     "description": "Azure storage connection string found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "GitHub Token", "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}",
     "description": "GitHub token found", "guideline_id": "CR-05.1"},
    {"name": "Stripe API Key", "pattern": r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{20,}",
     "description": "Stripe API key found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "Slack Token", "pattern": r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}",
     "description": "Slack API token found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "Slack Webhook", "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
     "description": "Slack webhook URL found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "RSA/DSA/EC Private Key", "pattern": r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----",
     "description": "Private key found embedded in file", "guideline_id": "CR-05.1"},
    {"name": "JWT Token", "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     "description": "JWT token found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "Password Assignment", "pattern": r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
     "description": "Password value found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "Secret/Token Assignment", "pattern": r"(?i)(?:secret|token|api_?key|auth_?key|access_?key|client_?secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
     "description": "Secret or API key found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "Database Connection String", "pattern": r"(?i)(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^:]+:[^@]+@[^\s'\"]+",
     "description": "Database connection string with credentials found", "guideline_id": "CR-05.1"},
    {"name": "Bearer Token in Code", "pattern": r"(?i)['\"]Bearer\s+[A-Za-z0-9\-._~+/]+=*['\"]",
     "description": "Bearer token found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "SendGrid API Key", "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
     "description": "SendGrid API key found hardcoded", "guideline_id": "CR-05.1"},
    {"name": "Twilio API Key", "pattern": r"SK[0-9a-fA-F]{32}",
     "description": "Twilio API key found hardcoded", "guideline_id": "CR-05.1"},
]

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".pyc", ".pyo", ".class", ".jar", ".war",
    ".dll", ".exe", ".so", ".dylib",
    ".lock", ".min.js", ".min.css",
}

MAX_SCAN_SIZE_KB = 500
IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", ".idea", ".vscode", "vendor",
}


def scan_for_secrets(target_path: str) -> str:
    """Scan a file or directory for hardcoded secrets.

    Args:
        target_path: Absolute path to a file or directory.

    Returns:
        JSON string with findings.
    """
    target = Path(target_path).resolve()
    if not target.exists():
        return json.dumps({"error": f"Path '{target_path}' does not exist.", "findings": [], "total_findings": 0})

    findings = []
    if target.is_file():
        findings.extend(_scan_file(target, target.parent))
    else:
        for root, dirs, filenames in os.walk(target):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in filenames:
                findings.extend(_scan_file(Path(root) / fname, target))

    return json.dumps({
        "total_findings": len(findings),
        "files_with_secrets": len(set(f["file_path"] for f in findings)),
        "findings": findings,
    }, indent=2)


def _scan_file(fpath: Path, base: Path) -> list[dict]:
    """Scan a single file for secret patterns."""
    ext = fpath.suffix.lower()
    if ext in SKIP_EXTENSIONS:
        return []
    try:
        if fpath.stat().st_size / 1024 > MAX_SCAN_SIZE_KB:
            return []
    except OSError:
        return []
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    rel_path = str(fpath.relative_to(base))
    findings = []

    for line_num, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        # Skip commented example lines
        if stripped.startswith("#") and ("example" in stripped.lower() or "todo" in stripped.lower()):
            continue
        for p in SECRET_PATTERNS:
            for match in re.finditer(p["pattern"], line):
                findings.append({
                    "file_path": rel_path,
                    "line": line_num,
                    "secret_type": p["name"],
                    "description": p["description"],
                    "evidence": _redact(match.group(0)),
                    "guideline_id": p["guideline_id"],
                    "severity": "CRITICAL",
                })
    return findings


def _redact(text: str) -> str:
    """Redact a secret value, showing only enough for identification."""
    if len(text) <= 8:
        return text[:2] + "***" + text[-2:]
    visible = max(4, len(text) // 5)
    return text[:visible] + "***REDACTED***" + text[-visible:]
