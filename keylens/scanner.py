"""Сканер файлов на предмет потенциально утекших секретов."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern[str]
    severity: str = "high"
    group: int = 0


PATTERNS: tuple[Pattern, ...] = (
    Pattern("GitHub PAT (classic)", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    Pattern("GitHub PAT (fine-grained)", re.compile(r"github_pat_[A-Za-z0-9_]{60,}")),
    Pattern("GitHub OAuth token", re.compile(r"gho_[A-Za-z0-9]{36}")),
    Pattern("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    Pattern("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    Pattern("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    Pattern("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b")),
    Pattern(
        "Private key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    Pattern(
        "Secret assignment",
        re.compile(
            r"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"
        ),
        severity="medium",
        group=1,
    ),
)

DEFAULT_EXCLUDE: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".idea",
        ".vscode",
    }
)

TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".bash",
        ".c",
        ".cfg",
        ".cpp",
        ".css",
        ".cs",
        ".env",
        ".go",
        ".gradle",
        ".h",
        ".hpp",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".kt",
        ".md",
        ".php",
        ".properties",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".sql",
        ".tf",
        ".toml",
        ".ts",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)

TEXT_NAMES: frozenset[str] = frozenset({"Dockerfile", "Makefile", ".env", ".gitignore"})


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    pattern: str
    severity: str
    match: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def mask(value: str) -> str:
    """Скрывает середину секрета, оставляя только начало и конец."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def is_text_file(path: Path) -> bool:
    return path.name in TEXT_NAMES or path.suffix.lower() in TEXT_EXTENSIONS


def scan_file(path: Path, root: Path) -> list[Finding]:
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, int, str, str]] = set()

    for line_no, line in enumerate(content.splitlines(), start=1):
        line_values: set[str] = set()
        for pattern in PATTERNS:
            for found in pattern.regex.finditer(line):
                value = found.group(pattern.group)
                key = (str(path), line_no, pattern.name, value)
                if key in seen:
                    continue
                # Общее правило не должно дублировать более конкретное.
                if pattern.severity == "medium" and any(
                    value in known or known in value for known in line_values
                ):
                    continue
                seen.add(key)
                line_values.add(value)
                findings.append(
                    Finding(
                        file=str(path.relative_to(root)) if path.is_relative_to(root) else str(path),
                        line=line_no,
                        pattern=pattern.name,
                        severity=pattern.severity,
                        match=mask(value),
                    )
                )
    return findings


def scan_path(
    target: str | Path,
    *,
    exclude: frozenset[str] | set[str] = DEFAULT_EXCLUDE,
    max_size: int = 2 * 1024 * 1024,
) -> tuple[list[Finding], int]:
    """Возвращает список находок и количество просканированных файлов."""
    root = Path(target).resolve()
    if root.is_file():
        files = [root]
        scan_root = root.parent
    else:
        scan_root = root
        files = []

    if root.is_dir():
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in exclude]
            for name in filenames:
                files.append(Path(dirpath) / name)

    results: list[Finding] = []
    scanned = 0
    for path in files:
        if not is_text_file(path):
            continue
        try:
            if path.stat().st_size > max_size:
                continue
        except OSError:
            continue
        scanned += 1
        results.extend(scan_file(path, scan_root))

    return results, scanned
