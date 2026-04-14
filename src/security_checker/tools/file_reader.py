"""FileReader — reads file contents with line numbers for security review.

Returns line-numbered content suitable for the AI assistant to reference
specific lines when reporting violations.
"""

from pathlib import Path

MAX_FILE_SIZE_KB = 500


def read_file_contents(file_path: str) -> str:
    """Read a file's contents with line numbers prepended.

    Args:
        file_path: Absolute path to the file to read.

    Returns:
        Line-numbered file contents, or an error message.
    """
    fpath = Path(file_path).resolve()

    if not fpath.exists():
        return f"Error: file '{file_path}' does not exist."
    if not fpath.is_file():
        return f"Error: '{file_path}' is not a file."

    try:
        size_kb = fpath.stat().st_size / 1024
    except OSError:
        return f"Error: cannot access '{file_path}'."

    if size_kb > MAX_FILE_SIZE_KB:
        return f"Error: file '{file_path}' is {size_kb:.0f}KB, exceeds {MAX_FILE_SIZE_KB}KB limit."

    # Try UTF-8 first, fall back to Latin-1
    try:
        content = fpath.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            content = fpath.read_text(encoding="latin-1")
        except Exception:
            return f"Error: file '{file_path}' appears to be binary."

    lines = content.splitlines()
    numbered = [f"{i:4d} | {line}" for i, line in enumerate(lines, 1)]
    header = f"--- {file_path} ({len(lines)} lines, {size_kb:.1f}KB) ---"
    return header + "\n" + "\n".join(numbered)
