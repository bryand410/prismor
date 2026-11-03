# Sentinel deployment

Deploys `PrismorAgentEvents_CL`, `PrismorAIInventory_CL`, a direct-ingestion data collection rule, the Monitoring Metrics Publisher role on that rule, and the workbook. Analytics rules are in `analytics/` and are listed in `bicep/content.generated.json`.

The sender needs **Monitoring Metrics Publisher** (`3913510d-42f4-4e42-8a64-420c390055eb`) on the **data collection rule only**.

API versions and a few output paths are still marked TODO in `bicep/main.bicep`. See `docs/sentinel.md`.

```bash
az login --tenant <HMLR_TENANT_ID>
az account set --subscription <SUB_ID>
az ad app create --display-name prismor-sentinel-ingest
az ad sp create --id <APP_ID>
az ad app credential reset --id <APP_ID> --cert @prismor-ingest.pem --append
SP_OBJECT_ID=$(az ad sp show --id <APP_ID> --query id -o tsv)

az bicep build --file packaging/sentinel/bicep/main.bicep
az deployment group what-if -g <RG> -f packaging/sentinel/bicep/main.bicep \
  -p workspaceName=<WS> senderPrincipalId=$SP_OBJECT_ID
az deployment group create -g <RG> -f packaging/sentinel/bicep/main.bicep \
  -p workspaceName=<WS> senderPrincipalId=$SP_OBJECT_ID --query properties.outputs
az deployment group create -g <RG> -f packaging/sentinel/bicep/content.bicep -p workspaceName=<WS>

prismor sentinel validate && prismor sentinel test
```

First ingestion can take several minutes. Then:

```kusto
PrismorAgentEvents_CL | where RuleId == "prismor-sentinel-test" | take 10
```

| Status | Meaning |
|---|---|
| 403 | The role assignment is missing or has not propagated yet. Wait, then retry. |
| 404 | Wrong DCR id, stream, or region. |
| 400 | Schema mismatch. Diff `prismor sentinel schema` against the rule. |

Regenerate the schema files with `prismor sentinel schema --write` after a column change. Regenerate `bicep/content.generated.json` with `python3 packaging/sentinel/tools/build_content.py`.
