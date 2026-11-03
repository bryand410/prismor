# Microsoft Sentinel

Prismor sends findings and inventory to Sentinel with the [Logs Ingestion API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview). The legacy HTTP Data Collector API is rejected. Its support ended on 2026-09-14 ([data collector API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api)).

Rows are written to a local spool first. A flush posts them. A failed flush leaves the rows on disk.

## Tables

| Table | Stream | When |
|---|---|---|
| `PrismorAgentEvents_CL` | `Custom-PrismorAgentEvents` | One row per finding or audit event |
| `PrismorAIInventory_CL` | `Custom-PrismorAIInventory` | One row per `prismor.inventory.v1` record |

`TimeGenerated` is set by the data collection rule from `EventTime` or `ObservedAt`. The client does not send it. `TenantId` and `Title` are reserved, so the columns are `EntraTenantId` and `FindingTitle`.

Copilot Studio rows use `InventorySource == "lowcode.copilot_studio"` (`collectors/copilot_studio.py`). `DeviceId` is `identity.load_identity()["device_id"]` when the machine is enrolled (`enterprise/identity.py`).

## Configure

```yaml
settings:
  outputs:
    - type: sentinel
      name: hmlr-sentinel
      endpoint: https://<dcr-or-dce-host>
      dcr_immutable_id: dcr-00000000000000000000000000000000
      auth:
        mode: client_certificate   # or client_secret, managed_identity, workload_identity
        tenant_id: 00000000-0000-0000-0000-000000000000
        client_id: 00000000-0000-0000-0000-000000000000
        certificate_file: C:\ProgramData\Prismor\sentinel\prismor-ingest.pfx
        certificate_password: ${PRISMOR_SENTINEL_CERT_PASSWORD}
      delivery: auto               # auto | system | background | inline
```

`delivery: auto` posts inline, unless a background worker is running (then it posts in the background) or the install is system-managed (then the user hook only appends, and `prismor system-sync` posts). `PRISMOR_SENTINEL_DELIVERY` overrides the setting. `PRISMOR_SENTINEL_DISABLE=1` skips the sink.

Certificate auth signs a PS256 client assertion. `auth.legacy_rs256: true` is the opt-in RS256 fallback. Managed identity uses App Service `IDENTITY_ENDPOINT` when that pair is set, and IMDS otherwise. Workload identity re-reads `AZURE_FEDERATED_TOKEN_FILE` on every token fetch.

TLS uses the same default `urllib` context as the other sinks (`prismor/runtime/sinks.py` does not install a custom SSL context), so `SSL_CERT_FILE` applies. The endpoint must be `https://`, except `127.0.0.1` when `PRISMOR_SENTINEL_ALLOW_INSECURE_LOCALHOST=1`.

## Commands

```bash
prismor sentinel validate
prismor sentinel test
prismor sentinel status --json
prismor sentinel flush
prismor sentinel schema --format bicep
```

`test` prints `204` and a KQL hint. It does not print the token. Exit `4` on HTTP 403 means the sender is missing the Monitoring Metrics Publisher role on the data collection rule.

Deploy the tables and the rule from `packaging/sentinel/`. The runbook is `packaging/sentinel/README.md`.

## Open verification

These spec items are not confirmed against a live tenant. The code follows the written default and marks the spot.

1. Azure Arc managed identity uses a challenge endpoint. Out of scope for v1.
2. No documented per-call record cap. The client still caps a batch at 500 records. [Service limits](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/service-limits).
3. No documented idempotency key. Delivery is at-least-once. [Logs Ingestion overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview).
4. HMLR workspace region (assumed UK South) and whether Private Link is required. Q3.
5. The exact Learn page for the IMDS token URL. The URL itself is the well-known `2018-02-01` metadata endpoint.
6. Container Apps token `api-version`. The code uses App Service `2019-08-01` when `IDENTITY_ENDPOINT` is set.
7. Whether a DCR immutable id is always `dcr-` plus 32 hex characters. A mismatch warns.
8. Managed-identity `resource` with or without a trailing slash. The client sends no slash. S-AUTH-05 pins that.
9. PS256 salt length. The client uses `PSS.DIGEST_LENGTH`. The Entra certificate-credentials page says PSS and does not spell the salt length.
10. Whether any tenant still requires RS256. Off unless `auth.legacy_rs256` is set.
11. Entra throttling around one token fetch per minute per device, at roughly 600 devices. No disk token cache in v1.
12. Stream type `datetime` versus table type `dateTime`. The schema files follow that split. S-SCH-02.
13. Whether the 1 MB Logs Ingestion limit is decimal. The hard ceiling is `1_000_000` bytes.
14. HTTP 200 and 202 are not documented for this upload API. They are treated as success. 204 is the documented success.
15. Whether a column missing from the stream declaration is dropped or rejected. The client does not rely on a drop. S-SCH keeps the schemas aligned.
16. Bicep API versions, `kind: Direct` together with `dataCollectionEndpointId`, the `logsIngestion` output paths, and `plan` / `totalRetentionInDays` on the table.
17. `Microsoft.SecurityInsights/alertRules` API version (the sketch uses a placeholder; content.bicep deploys the workbook and records the generated document).
18. `savedSearches` API version for the parser functions. The KQL is in `packaging/sentinel/parsers/`.
19. Workbooks API `2022-04-01`.
20. Scheduled-rule `queryPeriod` maximum of 14 days. The rules use `P14D` or less.
21. Which admin table HMLR has for hunting query H4 (`PowerPlatformAdminActivity` or `CloudAppEvents`). Q8. Scheduled rules use only the Prismor tables.
22. Workbook item type codes and parameter type `4`.
23. The current Content Hub / V3 packaging tool name. v1 ships Bicep.
24. NuGet package id `Microsoft.Azure.Kusto.Language`. The semantic job is `continue-on-error`.
25. Log Analytics query API URL used by the optional live poll.
26. Whether `az` is preinstalled on GitHub-hosted `ubuntu-latest`. The workflow runs `az bicep install`.
27. The Microsoft Learn page for AKS workload identity. The client follows the env vars in the Azure workload-identity Go sample cited by the spec.
28. The DCR logs-ingestion hostname shape `*.<region>-1.ingest.monitor.azure.com`.
29. How long a Monitoring Metrics Publisher assignment takes to propagate. The 403 hint tells the operator to retry.
