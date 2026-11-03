"""Offline KQL lint for Prismor Sentinel content.

Checks balanced brackets and quotes, known tables, and that column-like
identifiers used after where/by/project/on exist on the schema or were
defined in the query. It is a best-effort guard, not a Kusto compiler.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "bicep" / "schema"

KNOWN_TABLES = {
    "PrismorAgentEvents_CL", "PrismorAIInventory_CL", "IdentityInfo", "DeviceInfo",
    "CloudAppEvents", "SigninLogs", "AuditLogs", "PowerPlatformAdminActivity",
}
_STRING = re.compile(r"'(?:\\'|[^'])*'|\"(?:\\.|[^\"])*\"")
_COMMENT = re.compile(r"//.*?$", re.M)
_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def columns() -> set:
    names = set()
    for path in SCHEMA.glob("*.table.json"):
        for item in json.loads(path.read_text(encoding="utf-8")):
            names.add(item["name"])
    return names


def _strip(text: str) -> str:
    text = _COMMENT.sub("", text)
    return _STRING.sub("''", text)


def _defined(text: str) -> set:
    names = set()
    for match in re.finditer(r"\b(?:let|extend|summarize)\b([^|]*)", text):
        clause = match.group(1)
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=", clause):
            names.add(name)
    return names


def lint_text(text: str, known_columns: set, label: str = "") -> list:
    errors = []
    stripped = _strip(text)
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for lineno, line in enumerate(stripped.splitlines(), 1):
        for char in line:
            if char in "([{":
                stack.append((char, lineno))
            elif char in ")]}":
                if not stack or stack[-1][0] != pairs[char]:
                    errors.append(f"{label}:{lineno}: unbalanced '{char}'")
                else:
                    stack.pop()
    if stack:
        errors.append(f"{label}:{stack[-1][1]}: unclosed '{stack[-1][0]}'")
    defined = _defined(stripped)
    if re.search(r"\b(PrismorAgentEvents_CL|PrismorAIInventory_CL)\b", stripped):
        for lineno, line in enumerate(stripped.splitlines(), 1):
            for name in ("TenantId", "Title"):
                if re.search(rf"\b{name}\b", line):
                    errors.append(f"{label}:{lineno}: reserved column {name}")
    for lineno, line in enumerate(stripped.splitlines(), 1):
        for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*_CL)\b", line):
            if match.group(1) not in KNOWN_TABLES:
                errors.append(f"{label}:{lineno}: unknown table {match.group(1)}")
        for match in re.finditer(
            r"\b(?:where|by|project|on|extend)\s+([A-Z][A-Za-z0-9_]*)\b", line
        ):
            name = match.group(1)
            if name in known_columns or name in defined or name in KNOWN_TABLES:
                continue
            # `extend Name =` defines Name. The regex above also matches that
            # lhs; allow it when an equals sign follows.
            tail = line[match.end():].lstrip()
            if tail.startswith("=") and not tail.startswith("=="):
                continue
            errors.append(f"{label}:{lineno}: unknown column {name}")
    return errors


def main(argv: list) -> int:
    known = columns()
    paths = [Path(arg) for arg in argv[1:]] or list((ROOT / "analytics").glob("*.yaml"))
    failed = 0
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if path.suffix in {".yaml", ".yml"}:
            import yaml
            doc = yaml.safe_load(text) or {}
            text = str(doc.get("query") or "")
        problems = lint_text(text, known, str(path))
        for problem in problems:
            print(problem)
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
