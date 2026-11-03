# Shadow-agent discovery

`prismor discover` still inventories agents, MCP servers, and provider keys
and prints the legacy report. The surfaces below add a unified inventory
(`prismor.inventory.v1`, one JSON object per line) for a fleet that cannot
yet point the collector at a live tenant.

| Command | What it reads |
|---|---|
| `prismor discover endpoint --all-users` | Local profiles: agents, MCP configs, JetBrains, VS Code-family extensions, WSL homes |
| `prismor discover jetbrains` | JetBrains IDEs, AI Assistant, Junie, Copilot for JetBrains |
| `prismor discover extensions` | VS Code, Insiders, vscode-server, Cursor, Windsurf extension directories |
| `prismor discover wsl` | Running WSL distros only (`wsl.exe -l --running -q`) |
| `prismor discover copilot-studio` | Power Platform inventory API, Dataverse on 403 |
| `prismor discover inventory` | Whatever `inventory.yaml` lists under `surfaces` |

Output is a table on a terminal and NDJSON otherwise. `--format json|ndjson|table`,
`--out FILE`, `--sink NAME`, `--fail-on low|medium|high|critical`,
`--dry-run`, `--strict`. Exit codes: 0 ok, 1 risk threshold, 2 usage,
3 auth failure, 4 diagnostics with `--strict`.

Secrets are names only. Usernames are HMAC-SHA256 with the org salt
(`hash_users: true` by default). Commands go through `redact_command`, URLs
through `redact_url`.

## HMLR demo, fixtures only

There is no HMLR tenant in this repo. The demo reads
`tests/fixtures/inventory` and writes NDJSON plus the Sentinel-shaped rows
a sink would post. It does not call Microsoft.

```bash
python3 scripts/demo_hmlr_discovery.py --out /tmp/hmlr-demo
```

The same scan through the CLI:

```bash
PRISMOR_INVENTORY_OS=windows \
PRISMOR_INVENTORY_PROFILES=tests/fixtures/inventory/windows-dev/profiles \
PRISMOR_INVENTORY_WSL=tests/fixtures/inventory/windows-dev/wsl \
PRISMOR_INVENTORY_SALT=hmlr-demo \
PRISMOR_INVENTORY_HOSTNAME=LT-0420 \
PRISMOR_INVENTORY_MACHINE_ID=demo-machine \
PRISMOR_INVENTORY_HTTP_FIXTURE=tests/fixtures/inventory/copilot-studio \
python3 -m prismor.runtime.cli discover endpoint --all-users --format ndjson \
  --workspace tests/fixtures/inventory/windows-dev/workspace \
  --out /tmp/hmlr-endpoint.ndjson

PRISMOR_INVENTORY_OS=windows \
PRISMOR_INVENTORY_SALT=hmlr-demo \
PRISMOR_INVENTORY_HTTP_FIXTURE=tests/fixtures/inventory/copilot-studio \
python3 -m prismor.runtime.cli discover copilot-studio --api inventory --format ndjson \
  --out /tmp/hmlr-copilot.ndjson
```

`/tmp/hmlr-demo/summary.txt` from the script lists risk counts and points at
`packaging/sentinel/`. The analytics rules and hunting queries there are what
you deploy once a workspace exists. The fixture run writes a local
`sentinel-rows.json` instead of calling the Logs Ingestion API. See
[Sentinel](sentinel.md).

## Fleet

`prismor system-sync` (already scheduled every minute as SYSTEM) calls
`maybe_fleet_scan` when `inventory.yaml` exists and the interval has elapsed.
Results land in `<system directory>/inventory/last.ndjson`
(`C:\ProgramData\Prismor\inventory` on Windows,
`/Library/Application Support/Prismor/inventory` on macOS,
`/etc/prismor/inventory` on Linux). Intune passes `-Discover` and, optionally,
`-DiscoverSinks sentinel`. The Sentinel secret is
`PRISMOR_SENTINEL_SECRET`, not a value in the yaml file.

See [Deploy with Intune](deploy-intune.md) and [packaging/sentinel](../packaging/sentinel/README.md).

## Collector host

Copilot Studio, Entra, and the cloud collectors run once per organisation,
not on every endpoint. Use an admin workstation or a job with a managed
identity. Endpoint scans stay on the device.

## Unverified in this build

Items marked `verified: false` in `prismor/runtime/inventory/catalog/` still
match, with `confidence: unverified`. See the catalog NOTICE and the pull
request for the list. JetBrains `llm.mcpServers.xml` element names come from
published user configs; the official help page documents the JSON shape only.
The Dataverse environment-list api-version `2021-04-01` was not re-fetched
from a doc page. Cursor and Windsurf extension directories were not confirmed
against a current vendor doc.
