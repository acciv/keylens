"""Точка входа CLI: python -m keylens scan <path>."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .scanner import DEFAULT_EXCLUDE, mask, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keylens",
        description="Поиск утекших API-ключей и токенов в файлах и репозиториях.",
    )
    parser.add_argument("--version", action="version", version=f"keylens {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="просканировать путь")
    scan.add_argument("path", nargs="?", default=".", help="файл или каталог (по умолчанию .)")
    scan.add_argument("--json", action="store_true", help="вывод в формате JSON")
    scan.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="DIR",
        help="исключить каталог (можно повторять)",
    )
    scan.add_argument(
        "--max-size",
        type=int,
        default=2,
        metavar="MB",
        help="максимальный размер файла в МБ (по умолчанию 2)",
    )
    scan.add_argument("--quiet", action="store_true", help="только код возврата")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 2

    target = Path(args.path)
    if not target.exists():
        print(f"keylens: путь не найден: {target}", file=sys.stderr)
        return 2

    exclude = set(DEFAULT_EXCLUDE) | set(args.exclude)
    findings, scanned = scan_path(
        target,
        exclude=frozenset(exclude),
        max_size=args.max_size * 1024 * 1024,
    )

    if args.json:
        print(json.dumps([f.as_dict() for f in findings], ensure_ascii=False, indent=2))
    elif not args.quiet:
        print(f"🔍 keylens: просмотрено файлов: {scanned}")
        if findings:
            print(f"⚠️  Найдено потенциальных секретов: {len(findings)}\n")
            for finding in findings:
                print(
                    f"  [{finding.severity}] {finding.match:<28} "
                    f"{finding.file}:{finding.line} — {finding.pattern}"
                )
        else:
            print("✅ Секретов не найдено")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
