# Sentinel sink for Prismor inventory

`main.bicep` creates a data collection endpoint, the custom table
`PrismorAIInventory_CL`, and a data collection rule whose stream is
`Custom-PrismorAIInventory`. `transformKql` is `source` (rows are already
shaped by the sink).

The posting identity needs **Monitoring Metrics Publisher** on the data
collection rule. Client credentials read the secret from
`PRISMOR_SENTINEL_SECRET` (or Cloak). The secret is not written into the
rule, the settings file, or the inventory.

```bash
az deployment group what-if -g <resource-group> -f packaging/sentinel/main.bicep \
  -p workspaceName=<workspace> location=<region>
```

`queries.kql` holds the hunting queries (shadow by surface, new since
yesterday, high risk, Copilot Studio agents with `NO_AUTH`, MCP servers by
group). `analytics-rules.kql` holds the three scheduled-rule conditions:
new critical, new ungoverned Copilot Studio agent, and `PUBLIC_BIND`.
`workbook.json` is a small workbook with the shadow and high-risk views.

Usernames in the table are HMAC hashes (`UserHash`). The ingest payload is
scrubbed before it is sent.
