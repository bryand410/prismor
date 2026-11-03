#!/usr/bin/env python3
"""Write the HMLR demo fixtures. Safe to re-run. No secret values that are real.

The strings that look like secrets are canaries (they contain CANARY) so a
test can prove they never reach inventory output.
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "inventory"
WIN = ROOT / "windows-dev"
PROFILES = WIN / "profiles"
WSL = WIN / "wsl"
WS = WIN / "workspace"
API = ROOT / "copilot-studio"

CANARY_GHP = "ghp_CANARY" + ("A" * 30)
CANARY_ANT = "sk-ant-CANARY" + ("A" * 14)
CANARY_URL = "https://mcp.example.com/mcp?code=CANARYVALUE"


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(path: Path, payload) -> None:
    write(path, json.dumps(payload, indent=2) + "\n")


def plugin_jar(path: Path, plugin_id: str, name: str, version: str, vendor: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<idea-plugin>\n"
        f"  <id>{plugin_id}</id>\n"
        f"  <name>{name}</name>\n"
        f"  <version>{version}</version>\n"
        f"  <vendor>{vendor}</vendor>\n"
        "</idea-plugin>\n"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("META-INF/plugin.xml", xml)


def main() -> None:
    alice = PROFILES / "alice"
    bob = PROFILES / "bob"
    # Skipped profile names. They must not produce records.
    (PROFILES / "Public").mkdir(parents=True, exist_ok=True)
    (PROFILES / "Default").mkdir(parents=True, exist_ok=True)

    idea = alice / "AppData" / "Roaming" / "JetBrains" / "IntelliJIdea2026.2"
    plugin_jar(
        idea / "plugins" / "ai-assistant" / "lib" / "assistant.jar",
        "com.intellij.ml.llm", "JetBrains AI Assistant", "252.1", "JetBrains",
    )
    plugin_jar(
        idea / "plugins" / "junie" / "lib" / "junie.jar",
        "org.jetbrains.junie", "Junie", "252.61", "JetBrains",
    )
    plugin_jar(
        idea / "plugins" / "copilot" / "lib" / "copilot.jar",
        "com.github.copilot", "GitHub Copilot", "1.5.57", "GitHub",
    )
    write(
        idea / "options" / "llm.mcpServers.xml",
        """<?xml version="1.0" encoding="UTF-8"?>
<application>
  <component name="McpApplicationServerCommands">
    <McpServerCommand>
      <option name="enabled" value="true" />
      <option name="name" value="github" />
      <option name="programPath" value="npx" />
      <option name="arguments" value="-y @modelcontextprotocol/server-github" />
      <envs>
        <env name="GITHUB_TOKEN" value="%s" />
      </envs>
    </McpServerCommand>
  </component>
</application>
""" % CANARY_GHP,
    )
    write_json(alice / ".junie" / "mcp" / "mcp.json", {
        "mcpServers": {
            "context7": {
                "command": "npx",
                "args": ["-y", "@upstash/context7-mcp"],
                "env": {"CONTEXT7_API_KEY": CANARY_ANT},
            },
            "remote": {
                "url": CANARY_URL,
                "headers": {"Authorization": f"Bearer {CANARY_ANT}"},
            },
        }
    })
    write_json(alice / "AppData" / "Local" / "github-copilot" / "intellij" / "mcp.json", {
        "servers": {
            "github": {
                "type": "http",
                "url": "https://api.githubcopilot.com/mcp/",
                "headers": {"Authorization": f"Bearer {CANARY_GHP}"},
            }
        }
    })
    write_json(alice / ".kiro" / "settings" / "mcp.json", {
        "mcpServers": {"kiro-docs": {"command": "uvx", "args": ["mcp-server-git"]}}
    })
    write_json(alice / ".copilot" / "mcp-config.json", {
        "mcpServers": {"copilot-cli": {"command": "npx", "args": ["-y", "some-mcp-server@1.2.3"]}}
    })
    write_json(alice / ".codeium" / "windsurf" / "mcp_config.json", {
        "mcpServers": {"windsurf": {"command": "npx", "args": ["-y", "@windsurf/mcp@0.1.0"]}}
    })
    write_json(alice / ".gemini" / "antigravity" / "mcp_config.json", {
        "mcpServers": {"antigravity": {"url": "https://antigravity.example.com/mcp"}}
    })
    write_json(alice / ".aws" / "amazonq" / "mcp.json", {
        "mcpServers": {"amazonq": {"command": "q", "args": ["mcp"]}}
    })
    write_json(
        alice / "AppData" / "Roaming" / "Code" / "User" / "globalStorage"
        / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
        {"mcpServers": {"roo": {"command": "node", "args": ["server.js"], "alwaysAllow": ["*"]}}},
    )
    write(
        alice / ".bashrc",
        f"export OPENAI_API_KEY={CANARY_ANT}\nexport PATH=\"$PATH\"\n",
    )
    ext = alice / ".vscode" / "extensions"
    write_json(ext / "extensions.json", [{
        "identifier": {"id": "GitHub.copilot"},
        "version": "1.0.0",
        "relativeLocation": "github.copilot-1.0.0",
    }])
    write_json(ext / "github.copilot-1.0.0" / "package.json", {
        "name": "copilot",
        "publisher": "GitHub",
        "displayName": "GitHub Copilot",
        "version": "1.0.0",
    })
    write_json(ext / "local.heuristic-0.1.0" / "package.json", {
        "name": "heuristic",
        "publisher": "local",
        "displayName": "Local Model Tool",
        "version": "0.1.0",
        "contributes": {"languageModelTools": [{"name": "local.tool"}]},
    })
    write_json(bob / ".kiro" / "settings" / "mcp.json", {
        "mcpServers": {"bob-git": {"command": "uvx", "args": ["mcp-server-git"]}}
    })
    write_json(WS / ".junie" / "mcp" / "mcp.json", {
        "mcpServers": {
            "workspace": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}
        }
    })
    write_json(WSL / "Ubuntu" / "home" / "landreg" / ".kiro" / "settings" / "mcp.json", {
        "mcpServers": {"wsl-git": {"command": "uvx", "args": ["mcp-server-git"]}}
    })

    write_json(API / "page1.json", {
        "_source": "https://learn.microsoft.com/en-us/power-platform/admin/inventory-api",
        "totalRecords": 2,
        "count": 1,
        "resultTruncated": 1,
        "skipToken": "page2",
        "data": [{
            "id": "/microsoft.copilotstudio/agents/bot-inv-1",
            "name": "bot-inv-1",
            "type": "microsoft.copilotstudio/agents",
            "location": "uksouth",
            "properties": {
                "displayName": "Title assistant",
                "botId": "bot-inv-1",
                "environmentId": "env-hmlr-prod",
                "environmentName": "HMLR Prod",
                "createdBy": "alice.maker@landregistry.gov.uk",
                "ownerId": "owner-1",
                "createdAt": "2026-09-15T00:00:00Z",
                "lastModifiedAt": "2026-10-20T00:00:00Z",
                "lastPublishedAt": "2026-10-20T00:00:00Z",
                "isManaged": False,
                "entraAppId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "entraAgentId": "11111111-2222-3333-4444-555555555555",
                "schemaName": "cr_title",
            },
        }],
    })
    write_json(API / "page2.json", {
        "_source": "https://learn.microsoft.com/en-us/power-platform/admin/inventory-api",
        "totalRecords": 2,
        "count": 1,
        "skipToken": "",
        "data": [{
            "id": "/microsoft.copilotstudio/agents/bot-inv-2",
            "name": "bot-inv-2",
            "type": "microsoft.copilotstudio/agents",
            "location": "uksouth",
            "properties": {
                "displayName": "Search assistant",
                "botId": "bot-inv-2",
                "environmentId": "env-hmlr-prod",
                "createdAt": "2026-10-01T00:00:00Z",
                "lastPublishedAt": None,
                "entraAppId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "schemaName": "cr_search",
            },
        }],
    })
    write_json(API / "environments.json", {
        "_source": "https://learn.microsoft.com/en-us/power-platform/admin/manage-application-users",
        "value": [{
            "name": "env-hmlr-dev",
            "properties": {
                "displayName": "HMLR Dev",
                "linkedEnvironmentMetadata": {"instanceUrl": "https://hmlr.crm.dynamics.com"},
            },
        }],
    })
    write_json(API / "dataverse-bots.json", {
        "_source": "https://learn.microsoft.com/en-us/power-apps/developer/data-platform/reference/entities/bot",
        "value": [{
            "botid": "bot-0001",
            "name": "Land Registry assistant",
            "schemaname": "cr_landreg",
            "statecode": 0,
            "statuscode": 1,
            "publishedon": None,
            "modifiedon": "2026-10-01T00:00:00Z",
            "authenticationmode": 1,
            "authenticationtrigger": 0,
            "accesscontrolpolicy": 0,
            "language": 1033,
        }],
    })
    write_json(API / "botcomponents.json", {
        "_source": "https://learn.microsoft.com/en-us/power-apps/developer/data-platform/reference/entities/botcomponent",
        "value": [
            {
                "botcomponentid": "c1",
                "componenttype": 16,
                "name": "Public site",
                "schemaname": "cr_web",
                "data": "kind: public-website\nnote: OBI-RAW-MARKER\nsecret: " + CANARY_ANT + "\n",
            },
            {
                "botcomponentid": "c2",
                "componenttype": 9,
                "name": "Greet",
                "schemaname": "cr_greet",
                "data": "kind: topic\n",
            },
            {
                "botcomponentid": "c3",
                "componenttype": 17,
                "name": "On event",
                "schemaname": "cr_event",
                "data": "kind: event\n",
            },
            {
                "botcomponentid": "c4",
                "componenttype": 15,
                "name": "Maker connector",
                "schemaname": "cr_conn",
                "data": "connectionReference: maker-connection\nurl: " + CANARY_URL + "\n",
            },
        ],
    })
    write_json(API / "sentinel-429.json", {
        "_source": "https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview",
        "status": 429,
        "headers": {"Retry-After": "0"},
    })
    print(f"wrote fixtures under {ROOT}")


if __name__ == "__main__":
    main()
