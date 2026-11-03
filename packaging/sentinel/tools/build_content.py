"""Build the checked-in Sentinel content document. Deterministic."""
from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load_yaml_dir(path: Path) -> list:
    items = []
    for file in sorted(path.glob("*.yaml")):
        doc = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        doc["_file"] = file.name
        items.append(doc)
    return items


def build() -> dict:
    queries = {}
    qdir = ROOT / "workbooks" / "queries"
    if qdir.is_dir():
        for file in sorted(qdir.glob("*.kql")):
            queries[file.name] = file.read_text(encoding="utf-8").strip() + "\n"
    parsers = {}
    for file in sorted((ROOT / "parsers").glob("*.kql")):
        parsers[file.name] = file.read_text(encoding="utf-8").strip() + "\n"
    return {
        "contentVersion": "1.0.0",
        "analytics": load_yaml_dir(ROOT / "analytics"),
        "hunting": load_yaml_dir(ROOT / "hunting"),
        "parsers": parsers,
        "workbookQueries": queries,
    }


def main() -> None:
    payload = build()
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    (ROOT / "bicep" / "content.generated.json").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
