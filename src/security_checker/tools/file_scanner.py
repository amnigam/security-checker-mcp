"""FileScanner — walks directories, classifies files for security review.

Categorizes files into: source_code, config, ci_cd, dependency_manifest,
dockerfile. Maps each file to applicable security guideline domains.
"""

import json
import os
from pathlib import Path

IGNORE_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
    ".next", ".idea", ".vscode", "vendor", ".mypy_cache", ".pytest_cache",
    "egg-info", ".tox", ".nox", "coverage", ".coverage",
}

LANGUAGE_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
    ".cs": "csharp", ".go": "go", ".rb": "ruby", ".php": "php",
    ".rs": "rust", ".swift": "swift", ".kt": "kotlin",
}

CONFIG_EXTENSIONS = {
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties",
}

DEPENDENCY_FILES = {
    "package.json", "package-lock.json", "yarn.lock", "requirements.txt",
    "Pipfile", "Pipfile.lock", "poetry.lock", "pyproject.toml",
    "go.mod", "go.sum", "Gemfile", "Gemfile.lock", "pom.xml",
    "build.gradle", "composer.json", "composer.lock",
    "Cargo.toml", "Cargo.lock",
}

MAX_FILE_SIZE_KB = 500

# Domain codes applicable to each file type
SOURCE_CODE_DOMAINS = ["SM", "AU", "AZ", "IV", "XS", "AP", "CR", "EL", "SH", "FU", "DP"]
CONFIG_DOMAINS = ["SH", "CR", "SM", "EL"]
DEPENDENCY_DOMAINS = ["DS"]
DOCKERFILE_DOMAINS = ["CR", "EL"]
CI_CD_DOMAINS = ["CR", "DS"]


def scan_directory(target_path: str) -> str:
    """Scan a file or directory and classify all files for security review.

    Args:
        target_path: Absolute path to a file or directory.

    Returns:
        JSON string with classified files.
    """
    target = Path(target_path).resolve()
    if not target.exists():
        return json.dumps({"error": f"Path '{target_path}' does not exist.", "files": [], "total": 0})

    files = []
    if target.is_file():
        info = _classify_file(target, target.parent)
        if info:
            files.append(info)
    else:
        for root, dirs, filenames in os.walk(target):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in filenames:
                fpath = Path(root) / fname
                info = _classify_file(fpath, target)
                if info:
                    files.append(info)

    return json.dumps({"files": files, "total": len(files)}, indent=2)


def _classify_file(fpath: Path, base: Path) -> dict | None:
    """Classify a single file by type, language, and applicable domains."""
    try:
        size_kb = fpath.stat().st_size / 1024
        if size_kb > MAX_FILE_SIZE_KB:
            return None
    except OSError:
        return None

    rel_path = str(fpath.relative_to(base))
    fname = fpath.name.lower()
    ext = fpath.suffix.lower()

    # Dockerfile
    if fname in ("dockerfile", "containerfile"):
        return {"path": rel_path, "type": "dockerfile", "language": "dockerfile", "applicable_domains": DOCKERFILE_DOMAINS}

    # Dependency manifest
    if fname in {f.lower() for f in DEPENDENCY_FILES}:
        return {"path": rel_path, "type": "dependency_manifest", "language": ext.lstrip(".") or "text", "applicable_domains": DEPENDENCY_DOMAINS}

    # CI/CD
    if fname.endswith((".gitlab-ci.yml",)) or ".github" in str(fpath) or "ci" in fname or "pipeline" in fname or fname == "jenkinsfile":
        return {"path": rel_path, "type": "ci_cd", "language": "yaml", "applicable_domains": CI_CD_DOMAINS}

    # Nginx / Apache config
    if fname == "nginx.conf" or fname.endswith(".conf"):
        lang = "nginx" if "nginx" in fname else "config"
        return {"path": rel_path, "type": "config", "language": lang, "applicable_domains": CONFIG_DOMAINS}
    if fname == ".htaccess":
        return {"path": rel_path, "type": "config", "language": "apache", "applicable_domains": CONFIG_DOMAINS}

    # Config files
    if ext in CONFIG_EXTENSIONS or fname.startswith(".env"):
        return {"path": rel_path, "type": "config", "language": ext.lstrip(".") or "env", "applicable_domains": CONFIG_DOMAINS}

    # Source code
    if ext in LANGUAGE_MAP:
        return {"path": rel_path, "type": "source_code", "language": LANGUAGE_MAP[ext], "applicable_domains": SOURCE_CODE_DOMAINS}

    return None
