# Improvement Roadmap — Azure PaaS Integration

> **Scope:** This document describes the recommended improvements to evolve Azure Connectivity Doctor
> from a developer CLI tool into a first-class citizen of Azure PaaS hosting environments —
> specifically **Azure Container Apps** and **Azure App Service**.
>
> Each improvement area includes the problem it solves, the concrete change required, and an
> estimated implementation effort.

---

## Table of Contents

1. [Packaging & Deployment Model](#1-packaging--deployment-model)
2. [Configuration — Environment Variables](#2-configuration--environment-variables)
3. [Observability — Structured Output](#3-observability--structured-output)
4. [Identity — Managed Identity as First-Class Citizen](#4-identity--managed-identity-as-first-class-citizen)
5. [Scheduling & Continuous Monitoring](#5-scheduling--continuous-monitoring)
6. [Report Sink — Durable Output](#6-report-sink--durable-output)
7. [Pipeline Integration](#7-pipeline-integration-github-actions--azure-devops)
8. [Priority Matrix](#8-priority-matrix)
9. [Suggested Implementation Order](#9-suggested-implementation-order)

---

## 1. Packaging & Deployment Model

### Problem Today

The tool runs via `dotnet run` or a compiled local binary. PaaS operators cannot easily invoke it,
schedule it, or observe it without a .NET SDK on the host.

### Improvements

| # | Improvement | Details | Effort |
|---|---|---|---|
| 1.1 | **Add `Dockerfile`** | Multi-stage build using `mcr.microsoft.com/dotnet/sdk:10.0` to build and `mcr.microsoft.com/dotnet/runtime:10.0` as the runtime base. Makes the tool deployable as a **Container Apps Job** or **App Service WebJob** with no SDK on the host. | Small |
| 1.2 | **Self-contained single-file publish** | `dotnet publish -r linux-x64 --self-contained -p:PublishSingleFile=true`. No .NET runtime needed in the container — smaller image, faster cold start, no version mismatch risk. | Small |
| 1.3 | **Add `AzureConnectivityDoctor.Worker` project** | A `BackgroundService` host that runs the diagnostic pipeline on a configurable interval. Allows the tool to run as a long-lived **sidecar** in Container Apps, probing on a schedule and exporting metrics continuously. | Medium |
| 1.4 | **Add `Dockerfile.sidecar`** | Separate image for continuous worker vs. one-shot job usage, with its own `ENTRYPOINT` pointing at the Worker host. | Small |

### Example Dockerfile (one-shot job)

```dockerfile
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish src/AzureConnectivityDoctor.Cli \
    -c Release -r linux-x64 --self-contained \
    -p:PublishSingleFile=true \
    -o /app/publish

FROM mcr.microsoft.com/dotnet/runtime-deps:10.0
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["./AzureConnectivityDoctor.Cli"]
```

---

## 2. Configuration — Environment Variables

### Problem Today

All options are passed as CLI arguments (`--endpoint`, `--timeout`, `--identity`, etc.).
PaaS environments configure applications via **environment variables and App Settings**, not
shell invocations. There is currently no way to configure the tool from the Azure Portal,
Bicep/ARM templates, or Container Apps revision specs.

### Improvements

| # | Improvement | Details | Effort |
|---|---|---|---|
| 2.1 | **Bind `DoctorOptions` from environment variables** | Call `builder.Configuration.AddEnvironmentVariables("ACD_")` in the host builder. All existing options gain an env-var equivalent with no changes to the options model itself. | Small |
| 2.2 | **Support comma-separated `ACD_ENDPOINTS`** | Parse `ACD_ENDPOINTS=https://a.com,https://b.com` as a list — matches how App Service multi-value settings work. | Small |
| 2.3 | **Support `ACD_ENDPOINTS_FILE` pointing to a mounted volume path** | Container Apps supports volume mounts; this lets an operator mount an endpoints file from a Storage Account File Share. | Small |
| 2.4 | **Document all env vars in README** | Add a table of every `ACD_*` variable, its type, default, and CLI equivalent. | Small |

### Full Environment Variable Reference (proposed)

| Environment Variable | Type | Default | CLI Equivalent |
|---|---|---|---|
| `ACD_ENDPOINTS` | Comma-separated strings | _(none)_ | `--endpoint` |
| `ACD_ENDPOINTS_FILE` | File path | _(none)_ | `--endpoints-file` |
| `ACD_TIMEOUT` | Seconds (integer) | `10` | `--timeout` |
| `ACD_OVERALL_TIMEOUT` | Seconds (integer) | `0` (unlimited) | `--overall-timeout` |
| `ACD_MAX_CONCURRENCY` | Integer | `4` | `--concurrency` |
| `ACD_ENABLE_HTTP` | `true`/`false` | `false` | `--http` |
| `ACD_ENABLE_IDENTITY` | `true`/`false` | `false` | `--identity` |
| `ACD_ENABLE_AZURE_ASSESSMENT` | `true`/`false` | `false` | `--azure-assessment` |
| `ACD_MANAGED_IDENTITY_CLIENT_ID` | GUID string | _(none)_ | _(new — see §4)_ |
| `ACD_MARKDOWN_OUTPUT_PATH` | File path | _(none)_ | `--output` |
| `ACD_JSON_OUTPUT_PATH` | File path | _(none)_ | `--json-output` |
| `ACD_VERBOSE` | `true`/`false` | `false` | `--verbose` |

---

## 3. Observability — Structured Output

### Problem Today

The report is written to a Markdown file or stdout. In PaaS environments nobody reads files —
operators use **Application Insights**, **Log Analytics**, and **Prometheus**. The current output
format is invisible to Azure Monitor.

### Improvements

| # | Improvement | Details | Effort |
|---|---|---|---|
| 3.1 | **JSON console logging** | Add `builder.Logging.AddJsonConsole()` in Worker/Container mode. Container Apps Log Analytics ingests structured JSON from stdout/stderr automatically — zero infrastructure required. | Small |
| 3.2 | **Application Insights telemetry renderer** | Implement a new `IReportRenderer` that calls `TelemetryClient.TrackEvent("ACD.Finding", properties)` per finding and `TelemetryClient.TrackMetric("ACD.ProbeLatency", ms)` per stage. Enabled when `APPLICATIONINSIGHTS_CONNECTION_STRING` is set. | Medium |
| 3.3 | **Prometheus `/metrics` endpoint** | In Worker mode, expose a Prometheus metrics endpoint using `prometheus-net`. Emit a gauge per endpoint: `acd_endpoint_status{host="...", outcome="Succeeded"} 1`. Compatible with Container Apps managed Prometheus and Azure Monitor managed Prometheus. | Medium |
| 3.4 | **Azure Monitor custom metrics (REST)** | Post one metric per probe result to the Azure Monitor ingestion API. No SDK required — uses the managed identity already available in PaaS. Works from any hosting environment. | Medium |

### Existing Extension Point

The `IReportRenderer` interface (already in `Core/Reporting/`) is the correct place to attach
all new output targets. The pattern for additions is:

```
IReportRenderer
├── MarkdownReportRenderer   (exists)
├── JsonReportRenderer       (exists)
├── AppInsightsRenderer      (new — improvement 3.2)
└── PrometheusRenderer       (new — improvement 3.3)
```

> **Note:** Improvements 3.1 (JSON logs) and 3.2 (App Insights) together give complete
> end-to-end observability in Azure Monitor with a single Log Analytics workspace query.

---

## 4. Identity — Managed Identity as First-Class Citizen

### Problem Today

`DefaultAzureCredential` is used, which works in PaaS — but App Service and Container Apps
commonly have **user-assigned managed identities**. `DefaultAzureCredential` picks the
**system-assigned** identity by default; with multiple identities attached, it may pick the wrong
one silently. There is also no validation that the selected identity has the roles it needs before
the probe loop begins.

### Improvements

| # | Improvement | Details | Effort |
|---|---|---|---|
| 4.1 | **`--managed-identity-client-id` flag / `ACD_MANAGED_IDENTITY_CLIENT_ID` env var** | Pass the client ID to `ManagedIdentityCredential(clientId)` instead of `DefaultAzureCredential`. Solves the user-assigned MI selection problem. | Small |
| 4.2 | **Identity self-check stage** | Before the probe loop, acquire a token for `https://management.azure.com/` and log the token's `oid` (object ID) claim. Operators can confirm *which* identity is running without inspecting Azure Portal. Emit as a `DiagnosticStage.IdentitySelfCheck` finding. | Small |
| 4.3 | **Workload Identity support for AKS** | Accept `AZURE_CLIENT_ID` + `AZURE_FEDERATED_TOKEN_FILE` environment variables (already set by AKS Workload Identity webhook) and instantiate `WorkloadIdentityCredential`. | Small |
| 4.4 | **Role pre-flight check** | After acquiring a token, decode the `roles` claim and warn (not fail) if expected roles (`db_datareader`, `Azure Service Bus Data Receiver`) are absent. Surfaces RBAC misconfigurations before the probe fails. | Medium |

> **Important:** Improvement 4.1 is the single highest-priority identity change. Deployments
> with user-assigned managed identities will silently use the wrong identity without it.

---

## 5. Scheduling & Continuous Monitoring

### Problem Today

The tool is a one-shot process — it runs, produces a report, and exits. PaaS workloads require
**continuous health probing** to detect connectivity regressions between deployments.

### Deployment Patterns

#### Option A — Container Apps Job (recommended for scheduled batch runs)

Run the one-shot CLI image on a cron schedule. Zero always-on cost (billed per execution).
Results written to Storage or Log Analytics.

```yaml
# container-apps-job.yaml (proposed — does not exist yet)
properties:
  configuration:
    triggerType: Schedule
    scheduleTriggerConfig:
      cronExpression: "*/5 * * * *"   # every 5 minutes
    replicaTimeout: 120
  template:
    containers:
      - name: acd
        image: ghcr.io/org/azure-connectivity-doctor:latest
        env:
          - name: ACD_ENDPOINTS
            value: "https://myapp.azurewebsites.net,mydb.database.windows.net"
          - name: ACD_ENABLE_IDENTITY
            value: "true"
          - name: ACD_ENABLE_AZURE_ASSESSMENT
            value: "true"
```

#### Option B — Container Apps Sidecar (recommended for continuous monitoring)

Run the Worker image alongside your main application container. The sidecar probes the app's
dependencies on a configurable interval and exposes a `/health` endpoint that reflects
connectivity state. Your main app's **liveness probe** can depend on the sidecar's findings.

```yaml
# Sidecar added to existing Container App revision
containers:
  - name: my-app
    image: myapp:latest
  - name: connectivity-doctor-sidecar
    image: ghcr.io/org/azure-connectivity-doctor:sidecar-latest
    env:
      - name: ACD_PROBE_INTERVAL_SECONDS
        value: "60"
      - name: ACD_ENDPOINTS
        value: "mydb.database.windows.net,mybus.servicebus.windows.net"
```

#### Option C — App Service WebJob (simplest for App Service-hosted apps)

Package the self-contained binary as a **triggered WebJob**. Invoke it from a pipeline or on a
timer via the Kudu REST API (`POST /api/triggeredwebjobs/acd/run`).

---

## 6. Report Sink — Durable Output

### Problem Today

Reports go to a local file. In a stateless container, that file disappears when the container
restarts or is replaced during a revision update. There is no persistent, queryable record of
historical connectivity state.

### Improvements

| # | Improvement | Details | Effort |
|---|---|---|---|
| 6.1 | **Azure Blob Storage sink** | Upload `connectivity-report-{timestamp}.json` to a blob container after each run. Read from Azure Portal Storage Browser, download in a pipeline, or serve via a Static Website. | Small |
| 6.2 | **Azure Table Storage sink** | Write one row per endpoint per run (partitioned by `RunId`, row key `Host:Port`). Cheap, persistent, queryable from the Portal or `az storage entity query`. | Small |
| 6.3 | **Azure Monitor Logs ingestion (DCR)** | Push the JSON report to a Log Analytics custom table via the Logs Ingestion API. Enables full KQL queryability: trend analysis, alerting, dashboards. | Medium |
| 6.4 | **`IReportSink` abstraction** | Introduce `IReportSink` (parallel to `IReportRenderer`) with implementations for each target. Registered in DI — multiple sinks can be active simultaneously. | Small |

### Proposed `IReportSink` interface

```csharp
/// <summary>Writes a completed run report to a durable destination.</summary>
public interface IReportSink
{
    Task WriteAsync(RunReport report, CancellationToken cancellationToken);
}
```

---

## 7. Pipeline Integration (GitHub Actions / Azure DevOps)

### Problem Today

Exit codes are already meaningful (see `ExitCodes.cs`) — a `ConnectivityFailure` exit code will
fail a pipeline step. However, there is no published Docker image, no reusable pipeline action,
and no documented pattern for using the tool as a post-deployment gate.

### Improvements

| # | Improvement | Details | Effort |
|---|---|---|---|
| 7.1 | **GitHub Actions workflow to build and push Docker image** | `.github/workflows/docker-publish.yml` — builds and pushes to GHCR on every tag. | Small |
| 7.2 | **Reusable GitHub Actions composite action** | `action.yml` — wraps `docker run` with all `ACD_*` inputs exposed as action inputs. Operators add one `uses:` step to their deployment workflow. | Small |
| 7.3 | **Azure DevOps pipeline task** | A YAML task template that pulls the image and runs it as a post-deployment connectivity gate. | Small |
| 7.4 | **Exit code documentation in README** | Document all exit codes and their pipeline meanings explicitly in the README. | Trivial |

### Example GitHub Actions post-deploy gate (proposed)

```yaml
- name: Post-deploy connectivity check
  uses: org/azure-connectivity-doctor@v1
  with:
    endpoints: |
      https://${{ vars.APP_HOSTNAME }}
      ${{ vars.SQL_HOST }}.database.windows.net
    enable-identity: true
    timeout: 15
  # Step fails the deployment if exit code is ConnectivityFailure (2)
```

---

## 8. Priority Matrix

Each improvement plotted by **implementation effort** (horizontal) vs. **operational impact for
a PaaS-hosted workload** (vertical). Items in the top-left deliver the highest return on investment.

```
                        Low Effort          Medium Effort       High Effort
                   ┌──────────────────┬──────────────────┬──────────────────┐
  High Impact      │ 4.1 MI clientId  │ 3.2 App Insights │ 1.3 Worker proj  │
                   │ 1.1 Dockerfile   │ 5A CA Job YAML   │ 5B Sidecar       │
                   │ 2.1 Env vars     │ 6.1 Blob sink    │ 3.3 Prometheus   │
                   │ 1.2 Self-contain │                  │                  │
                   │ 3.1 JSON logs    │                  │                  │
                   ├──────────────────┼──────────────────┼──────────────────┤
  Medium Impact    │ 4.2 Identity chk │ 6.2 Table sink   │ 6.3 Log ingest   │
                   │ 4.3 Workload ID  │ 3.4 AM metrics   │ 4.4 Role preflt  │
                   │ 6.4 IReportSink  │                  │                  │
                   ├──────────────────┼──────────────────┼──────────────────┤
  Lower Impact     │ 7.4 Exit docs    │ 7.2 GH Action    │ 7.3 ADO task     │
                   │ 7.1 Docker push  │                  │                  │
                   └──────────────────┴──────────────────┴──────────────────┘
```

---

## 9. Suggested Implementation Order

Work is grouped into **phases** so that each phase is independently shippable and builds on the
previous one.

### Phase 1 — Deployable (1–2 days)

> **Goal:** The tool can be run in any PaaS environment without a .NET SDK.

- [ ] **1.2** Self-contained single-file publish configuration in `.csproj`
- [ ] **1.1** `Dockerfile` (multi-stage, linux-x64)
- [ ] **2.1** Environment variable binding (`ACD_*` prefix via `AddEnvironmentVariables`)
- [ ] **2.2** Comma-separated `ACD_ENDPOINTS` support
- [ ] **7.1** GitHub Actions workflow to build and push Docker image to GHCR

### Phase 2 — Observable (2–3 days)

> **Goal:** Every run is visible in Azure Monitor with no manual log inspection.

- [ ] **3.1** JSON console logging (structured, Container Apps-compatible)
- [ ] **4.1** `ACD_MANAGED_IDENTITY_CLIENT_ID` / `--managed-identity-client-id`
- [ ] **4.2** Identity self-check stage (log the running identity's object ID)
- [ ] **6.4** `IReportSink` abstraction
- [ ] **6.1** Azure Blob Storage sink

### Phase 3 — Scheduled & Durable (3–5 days)

> **Goal:** The tool runs continuously and stores a queryable history of connectivity state.

- [ ] **1.3** `AzureConnectivityDoctor.Worker` project (`BackgroundService`)
- [ ] **1.4** `Dockerfile.sidecar`
- [ ] **5A** Container Apps Job YAML example (`infra/container-apps-job.yaml`)
- [ ] **6.2** Azure Table Storage sink
- [ ] **5B** Container Apps sidecar YAML example (`infra/container-apps-sidecar.yaml`)

### Phase 4 — Integrated & Alerting (1 week+)

> **Goal:** Full observability and automated alerting on connectivity regressions.

- [ ] **3.2** Application Insights telemetry renderer (`IReportRenderer` implementation)
- [ ] **3.3** Prometheus `/metrics` endpoint in Worker mode
- [ ] **6.3** Azure Monitor Logs ingestion (DCR) sink
- [ ] **4.4** Role pre-flight check (warn on missing RBAC roles)
- [ ] **7.2** Reusable GitHub Actions composite action
- [ ] **7.3** Azure DevOps pipeline task template

---

> **Tip:** Phase 1 alone — `Dockerfile` + env var binding — is sufficient to deploy the tool as a
> **Container Apps Job** today. All subsequent phases add observability and durability on top
> of that foundation. Start there.

---

*Last updated: October 2026*
*Author: Azure Connectivity Doctor development team*
