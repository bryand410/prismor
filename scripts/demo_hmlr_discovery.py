#!/usr/bin/env python3
"""HMLR shadow-agent demo. Reads fixtures only. Does not call Microsoft.

    python3 scripts/demo_hmlr_discovery.py --out /tmp/hmlr-demo
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from prismor.runtime.inventory.context import ScanContext  # noqa: E402
from prismor.runtime.inventory.runner import _fixture_http, run  # noqa: E402
from prismor.runtime.inventory.schema import to_ndjson  # noqa: E402
from prismor.runtime.sentinel.mapping import to_inventory_row  # noqa: E402

FIXTURE = _REPO / "tests" / "fixtures" / "inventory"
CANARY = "CANARY"


def _context(api: str) -> ScanContext:
    ctx = ScanContext(
        os_name="windows",
        workspace=FIXTURE / "windows-dev" / "workspace",
        all_users=True,
        hash_users=True,
        org_salt="hmlr-demo",
        hostname="LT-0420",
        machine_id="demo-machine",
        profiles_root=FIXTURE / "windows-dev" / "profiles",
        wsl_root=FIXTURE / "windows-dev" / "wsl",
        fixture_http=True,
        copilot_studio={"api": api, "tenant_id": "hmlr-tenant"},
        auth={"mode": "fixture", "tenant": "hmlr-tenant"},
    )
    ctx.http = _fixture_http(FIXTURE / "copilot-studio")
    return ctx


def main() -> int:
    parser = argparse.ArgumentParser(description="HMLR shadow-agent demo from fixtures")
    parser.add_argument("--out", default="/tmp/hmlr-demo", help="Directory for NDJSON and the summary")
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    endpoint = run(["endpoint"], _context("inventory"))
    copilot = run(["copilot-studio"], _context("inventory"))
    dataverse = run(["copilot-studio"], _context("dataverse"))
    rows = [record.to_dict() for record in endpoint + copilot + dataverse]
    blob = json.dumps(rows)
    if CANARY in blob:
        sys.stderr.write("demo output contains a canary secret marker\n")
        return 1
    (out / "endpoint.ndjson").write_text(to_ndjson(endpoint), encoding="utf-8")
    (out / "copilot-studio.ndjson").write_text(to_ndjson(copilot), encoding="utf-8")
    (out / "dataverse.ndjson").write_text(to_ndjson(dataverse), encoding="utf-8")
    sentinel = [to_inventory_row(row) for row in rows]
    (out / "sentinel-rows.json").write_text(json.dumps(sentinel, indent=2) + "\n", encoding="utf-8")
    counts = Counter(row.get("kind") for row in rows)
    levels = Counter((row.get("risk") or {}).get("level") for row in rows)
    users = sorted({(row.get("location") or {}).get("user") for row in rows if (row.get("location") or {}).get("user")})
    summary = [
        "HMLR shadow-agent demo (fixtures only, no tenant)",
        f"records: {len(rows)}",
        "kinds: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())),
        "risk: " + ", ".join(f"{k}={v}" for k, v in sorted(levels.items())),
        f"distinct user hashes: {len(users)}",
        "Sentinel queries: packaging/sentinel/queries.kql",
        "Local stand-in for the Logs Ingestion payload: sentinel-rows.json",
    ]
    text = "\n".join(summary) + "\n"
    (out / "summary.txt").write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
