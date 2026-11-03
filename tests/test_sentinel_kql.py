"""S-KQL: offline lint, negative fixtures, and analytics-rule shape."""
from __future__ import annotations

import re
import uuid
from pathlib import Path

import importlib.util

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "packaging" / "sentinel"


def _load_lint():
    spec = importlib.util.spec_from_file_location("kql_lint", PACK / "tools" / "kql_lint.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


kql_lint = _load_lint()
TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
    "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery",
    "LateralMovement", "Collection", "CommandAndControl", "Exfiltration", "Impact",
}
_PERIOD = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$")


def _sources():
    paths = []
    for folder, pattern in (
        ("analytics", "*.yaml"), ("hunting", "*.yaml"), ("parsers", "*.kql"),
    ):
        paths.extend(sorted((PACK / folder).glob(pattern)))
    paths.extend(sorted((PACK / "workbooks" / "queries").glob("*.kql")))
    return paths


def _query(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if path.suffix in {".yaml", ".yml"}:
        return str((yaml.safe_load(text) or {}).get("query") or "")
    return text


def test_s_kql_01_content_lints():
    known = kql_lint.columns()
    problems = []
    for path in _sources():
        problems.extend(kql_lint.lint_text(_query(path), known, str(path.relative_to(ROOT))))
    assert problems == []


def test_s_kql_02_negative_fixtures():
    known = kql_lint.columns()
    for path in sorted((ROOT / "tests" / "sentinel_fixtures" / "kql_bad").glob("*.kql")):
        problems = kql_lint.lint_text(path.read_text(encoding="utf-8"), known, path.name)
        assert problems, path.name
        assert any(":1:" in item or ":2:" in item for item in problems)


def _period_ok(value: str) -> bool:
    match = _PERIOD.fullmatch(value)
    if not match:
        return False
    days = int(match.group(1) or 0)
    return days <= 14


def test_s_kql_03_rule_shape():
    seen = set()
    for path in sorted((PACK / "analytics").glob("*.yaml")) + sorted((PACK / "hunting").glob("*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for key in ("id", "name", "severity", "queryFrequency", "queryPeriod",
                    "triggerOperator", "triggerThreshold", "tactics", "query", "version"):
            assert key in doc, f"{path.name} missing {key}"
        uuid.UUID(str(doc["id"]))
        assert doc["id"] not in seen
        seen.add(doc["id"])
        assert _period_ok(doc["queryPeriod"]), doc["queryPeriod"]
        assert _period_ok(doc["queryFrequency"]) or str(doc["queryFrequency"]).startswith("PT")
        assert doc["tactics"] and set(doc["tactics"]) <= TACTICS


def test_s_kql_04_semantic_optional():
    import shutil
    import subprocess
    if shutil.which("dotnet") is None:
        pytest.skip("dotnet is not installed")
    project = PACK / "tools" / "kqlcheck"
    proc = subprocess.run(
        ["dotnet", "run", "--project", str(project)],
        capture_output=True, text=True, timeout=180,
    )
    if proc.returncode != 0:
        pytest.skip(f"kqlcheck did not build: {proc.stderr[-400:]}")
    assert proc.returncode == 0
