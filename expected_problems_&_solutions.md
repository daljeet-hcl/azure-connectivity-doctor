# Expected Problems & Solutions — Azure Connectivity Doctor

> **Audience:** Future maintainers and contributors to this project.
>
> **Purpose:** This document captures the production failure modes that are *anticipated* when
> this tool is deployed against real, locked-down enterprise Azure tenants. Each problem is paired
> with a concrete fix direction and, where applicable, a pointer to the relevant source file or
> roadmap item.
>
> Keep this document updated as problems are resolved or new ones are discovered.

---

## Quick-Reference Problem Matrix

| # | Problem | Severity | Fix Effort |
|---|---|:---:|:---:|
| [P1](#p1--wrong-managed-identity-selected) | Wrong Managed Identity selected silently | 🔴 High | Small |
| [P2](#p2--token-scope-mismatch-in-sovereign--gov-clouds) | Token scope wrong in sovereign/Gov clouds | 🔴 High | Small |
| [P3](#p3--defaultazurecredential-discovery-hangs-in-headless-compute) | `DefaultAzureCredential` discovery hang on headless VMs | 🟠 Medium | Small |
| [P4](#p4--missing-rbac-roles-are-only-discovered-at-probe-time) | Missing RBAC roles surface only as probe failures | 🟠 Medium | Medium |
| [P5](#p5--sql-firewall-blocks-the-probe-without-identifying-the-egress-ip) | SQL Firewall block gives no egress-IP guidance | 🟠 Medium | Small |
| [P6](#p6--reports-are-lost-when-containers-restart) | Reports written to local files disappear in containers | 🟠 Medium | Medium |
| [P7](#p7--runs-are-invisible-to-azure-monitor) | Runs are invisible to Azure Monitor / App Insights | 🟠 Medium | Medium |
| [P8](#p8--sensitive-internal-hostnames-and-ips-in-reports) | Sensitive internal hostnames/IPs leak into reports | 🟡 Low-Med | Small |
| [P9](#p9--arm-assessment-calls-can-trigger-subscription-throttling) | ARM assessment calls trigger 429 throttling | 🟡 Low-Med | Small |
| [P10](#p10--default-concurrency-is-too-low-for-large-endpoint-lists) | Default concurrency of 4 too low for large endpoint lists | 🟡 Low | Trivial |
| [P11](#p11--default-10s-timeout-is-too-aggressive-for-high-latency-paths) | Default 10s timeout fires false alarms on VPN/WAN paths | 🟡 Low | Trivial |
| [P12](#p12--no-dockerfile-or-env-var-support-for-paas-deployment) | No Dockerfile or env-var binding for PaaS deployment | 🟡 Low | Small |

---

## P1 — Wrong Managed Identity Selected

### Symptom

Token acquisition succeeds (exit code 0), but all authenticated probes (`ACD-IDENTITY-REJECTED`,
`ACD-SQL-FIREWALL`, `ACD-SB-UNAUTHORIZED`) fail immediately. The operator cannot tell whether the
problem is a network rule or an identity/RBAC problem.

### Root Cause

Enterprise Azure deployments commonly attach **multiple managed identities** to a single host —
one system-assigned and one or more user-assigned, each with different RBAC scopes.

[`CredentialProvider.cs`](file:///src/AzureConnectivityDoctor.Core/Identity/CredentialProvider.cs)
constructs a `DefaultAzureCredential`. When `ManagedIdentityClientId` is not supplied,
`DefaultAzureCredential` selects the **system-assigned** identity, which may have zero roles on
the resources being probed. The token is valid but authorises the wrong principal.

This is also flagged as the **single highest-priority identity change** in
[`improvement_roadmap.md §4`](file:///improvement_roadmap.md).

### Fix Direction

1. **Expose `--managed-identity-client-id <GUID>` as a required-or-recommended CLI flag** when
   running against enterprise tenants. The option already exists in `DoctorOptions` and flows
   into `CredentialProvider` — it just needs prominent documentation and a warning when omitted
   in a PaaS context.

2. **Add `ACD_MANAGED_IDENTITY_CLIENT_ID` environment variable binding** (roadmap item 2.1 / 4.1)
   so operators can set this once in an App Settings / Container Apps secret rather than in every
   CLI invocation.

3. **Emit an identity self-check finding** that decodes the acquired JWT and logs the `oid`
   (object ID) and `appid` claims. This lets an operator confirm which principal is running
   without opening the Azure Portal. (roadmap item 4.2)

```csharp
// CredentialProvider.cs — the path for user-assigned MI is already coded:
if (!string.IsNullOrWhiteSpace(value.ManagedIdentityClientId))
{
    credentialOptions.ManagedIdentityClientId = value.ManagedIdentityClientId;
}
// The problem is that operators do not know they must supply this in multi-MI environments.
```

**Operational rule:** Always supply `--managed-identity-client-id` when running against any
enterprise tenant. Never rely on system-assigned identity as the default in production.

---

## P2 — Token Scope Mismatch in Sovereign / Gov Clouds

### Symptom

`ACD-IDENTITY-REJECTED` on every authenticated probe despite the identity having the correct
RBAC roles in the Portal. The error from the service is `401 Unauthorized` with an
`invalid_audience` detail in the response body (only visible with `--verbose`).

### Root Cause

[`AzureScopes.cs`](file:///src/AzureConnectivityDoctor.Core/Identity/AzureScopes.cs) hardcodes
commercial-cloud audience URIs:

| Scope | Commercial | Azure Government |
|---|---|---|
| SQL | `https://database.windows.net/.default` | `https://database.usgovcloudapi.net/.default` |
| Service Bus | `https://servicebus.windows.net/.default` | `https://servicebus.usgovcloudapi.net/.default` |
| ARM | `https://management.azure.com/.default` | `https://management.usgovcloudapi.net/.default` |

A token minted for the commercial audience is silently rejected by Gov-cloud services.

### Fix Direction

1. Add an `AzureCloud` enum (`Commercial`, `Government`, `China`) to `DoctorOptions`.
2. Add a `--azure-cloud` CLI flag and `ACD_AZURE_CLOUD` env var.
3. Update `AzureScopes` to return the correct audience based on the configured cloud:

```csharp
public static string ForSql(AzureCloud cloud) => cloud switch
{
    AzureCloud.Government => "https://database.usgovcloudapi.net/.default",
    AzureCloud.China      => "https://database.chinacloudapi.cn/.default",
    _                     => "https://database.windows.net/.default"
};
```

Alternatively, derive the resource URI from `AzureAuthorityHosts` (already in the
`Azure.Identity` package) to avoid maintaining the mapping manually.

---

## P3 — `DefaultAzureCredential` Discovery Hangs in Headless Compute

### Symptom

The tool starts, then stalls for 10–30 seconds before the first probe result appears. With
`--verbose`, the log shows multiple credential sources being tried sequentially and timing out.

### Root Cause

`DefaultAzureCredential` walks a chain of ~9 credential sources. Even with
`ExcludeInteractiveBrowserCredential = true` (already set in `CredentialProvider`), it still
probes Azure CLI, Visual Studio, Visual Studio Code, Azure PowerShell, and the shared token cache
— all of which call out-of-process binaries or read files that do not exist in a clean container
or CI agent. Each failed probe adds latency to the first token acquisition.

### Fix Direction

Detect the hosting environment and exclude developer-machine credential sources when running
in a container or managed-identity context:

```csharp
// In CredentialProvider.cs:
bool isContainerEnv =
    !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("IDENTITY_ENDPOINT")) ||  // App Service / Container Apps MI
    !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("AZURE_FEDERATED_TOKEN_FILE")); // AKS Workload Identity

if (isContainerEnv)
{
    credentialOptions.ExcludeAzureCliCredential          = true;
    credentialOptions.ExcludeVisualStudioCredential      = true;
    credentialOptions.ExcludeVisualStudioCodeCredential  = true;
    credentialOptions.ExcludeSharedTokenCacheCredential  = true;
    credentialOptions.ExcludeAzurePowerShellCredential   = true;
}
```

When `ACD_MANAGED_IDENTITY_CLIENT_ID` is explicitly set, consider using `ManagedIdentityCredential`
directly instead of `DefaultAzureCredential` to eliminate discovery overhead entirely.

Also see roadmap item **4.3** (Workload Identity support for AKS).

---

## P4 — Missing RBAC Roles Are Only Discovered at Probe Time

### Symptom

The probe fails with `ACD-IDENTITY-REJECTED` or `ACD-SQL-LOGIN-DENIED`. The operator knows the
identity is wrong but cannot tell *which* role is missing or on *which* scope without going into
the Azure Portal.

### Root Cause

There is no pre-flight role check. The tool acquires a token and immediately attempts the probe.
Only when the service returns an authorization error does the operator learn that a role assignment
is missing.

### Fix Direction

After acquiring a token, **decode the JWT payload client-side** (no extra HTTP call needed) and
emit the claims as a diagnostic finding:

```csharp
// Decode base64url-encoded JWT payload segment:
string payloadJson = Encoding.UTF8.GetString(
    Convert.FromBase64String(PadBase64(token.Split('.')[1])));

using var doc = JsonDocument.Parse(payloadJson);
string oid   = doc.RootElement.GetProperty("oid").GetString() ?? "unknown";
string appId = doc.RootElement.GetProperty("appid").GetString() ?? "unknown";
// Emit as ACD-IDENTITY-SELF-CHECK finding with severity = Info

// Optionally, check doc.RootElement.TryGetProperty("roles", out var roles)
// and emit ACD-IDENTITY-MISSING-ROLE warning if expected roles are absent.
```

Emit this as a **warning-severity finding** (never an error) so that RBAC problems are surfaced
before the operator interprets probe failures as network issues.

See roadmap item **4.4** (Role pre-flight check).

---

## P5 — SQL Firewall Blocks the Probe Without Identifying the Egress IP

### Symptom

`ACD-SQL-FIREWALL` is reported. The operator must manually determine what IP address the tool was
running from in order to know what to ask the DBA team to whitelist.

### Root Cause

[`SqlProbe.cs`](file:///src/AzureConnectivityDoctor.Core/Probes/SqlProbe.cs) returns a generic
remediation message:
> *"Add a firewall rule, or allow Azure services, or connect through a private endpoint."*

It does not include the actual egress IP that was rejected. The operator must run a separate
`curl https://checkip.azure.com` from the same host to find this — which may not be possible
during an incident.

### Fix Direction

At startup (before the probe loop), resolve the tool's public egress IP using an Azure-native
service:

```csharp
// In DiagnosticRunner or a new EgressIpDetector service:
using var client = new HttpClient();
string? egressIp = await client.GetStringAsync(
    "https://checkip.azure.com", cancellationToken);
// Store in RunReport and inject into ACD-SQL-FIREWALL finding evidence.
```

Include it in the `ACD-SQL-FIREWALL` finding:
> *"The server firewall rejected egress IP `20.x.x.x`. Supply this IP to the DBA team to add
> a server-level firewall rule, or deploy the tool inside the approved VNet subnet."*

---

## P6 — Reports Are Lost When Containers Restart

### Symptom

After a Container Apps Job or App Service WebJob run completes, the `connectivity-report.json`
and `connectivity-report.md` files are gone. There is no historical record of connectivity state.

### Root Cause

Reports are written to the **current working directory** of the process. Container filesystems are
ephemeral — files are destroyed when the container stops or is replaced during a revision update.

### Fix Direction

Implement the `IReportSink` abstraction and an Azure Blob Storage sink (roadmap items **6.4**
and **6.1**):

```csharp
public interface IReportSink
{
    Task WriteAsync(RunReport report, CancellationToken cancellationToken);
}

// BlobStorageSink implementation:
// - Activated when ACD_REPORT_BLOB_CONTAINER_URL is set.
// - Uploads connectivity-report-{timestamp}.json using the same MI credential
//   that is already in use for probing.
// - File and BlobStorageSink can be active simultaneously (multiple sinks).
```

The `IReportRenderer` pattern (Markdown + JSON renderers) already establishes the right
abstraction. `IReportSink` is its durable-output counterpart.

See also roadmap item **6.2** (Azure Table Storage sink) and **6.3** (Log Analytics ingestion)
for queryable historical state.

---

## P7 — Runs Are Invisible to Azure Monitor

### Symptom

SREs have no way to alert on `ACD-TCP-BLOCKED` or `ACD-SQL-FIREWALL` findings. There is no
trend data. Connectivity regressions are only detected when an application reports an error —
not proactively.

### Root Cause

All output goes to local files or stdout. Enterprise operations teams use **Log Analytics**,
**Application Insights**, and **Azure Monitor alert rules** — not flat files. The tool is
currently invisible to these systems.

### Fix Direction

Two complementary steps, in priority order:

#### Step 1 — Structured JSON console logging (small effort, high impact)

Add `builder.Logging.AddJsonConsole()` in the host builder. Container Apps Log Analytics
automatically ingests structured JSON from stdout with zero infrastructure changes. This
immediately makes every run's findings KQL-queryable:

```kql
ContainerAppConsoleLogs_CL
| where Message contains "ACD-TCP-BLOCKED"
| summarize count() by bin(TimeGenerated, 5m), tostring(parse_json(Message).host)
```

See roadmap item **3.1**.

#### Step 2 — Application Insights telemetry renderer (medium effort, high impact)

Implement `AppInsightsRenderer : IReportRenderer` that emits one `TrackEvent` per finding and
one `TrackMetric` per probe stage. Activated when `APPLICATIONINSIGHTS_CONNECTION_STRING` is set:

```csharp
_telemetry.TrackEvent("ACD.Finding", new Dictionary<string, string> {
    ["code"]     = finding.Code,
    ["severity"] = finding.Severity.ToString(),
    ["host"]     = target.Host,
    ["port"]     = target.Port.ToString()
});
_telemetry.TrackMetric("ACD.ProbeLatency.TcpMs", stage.DurationMilliseconds,
    new Dictionary<string, string> { ["host"] = target.Host });
```

See roadmap item **3.2**. The `IReportRenderer` extension point for this already exists in
`Core/Reporting/`.

---

## P8 — Sensitive Internal Hostnames and IPs in Reports

### Symptom

The generated `connectivity-report.json` and `connectivity-report.md` contain internal FQDNs
and RFC 1918 IP addresses resolved by DNS. These may be confidential (internal network topology,
private endpoint addresses, naming conventions that reveal infrastructure layout).

If reports are shared with external support teams or stored in a shared log sink, internal
topology is inadvertently disclosed.

### Root Cause

`SecretRedactor` targets credential patterns (passwords, bearer tokens, connection strings) but
does not suppress or anonymize hostnames or resolved IP addresses.

### Fix Direction

1. **Short-term (documentation):** Add a clear warning in the README that generated reports
   contain internal network topology and should be treated as *internal/confidential*. Do not
   share externally without review.

2. **Medium-term (feature):** Add a `--sanitize-report` flag that replaces RFC 1918 IP addresses
   with anonymized labels (e.g., `<private-ip-1>`) and non-public FQDNs with `<internal-host-N>`
   in both the Markdown and JSON outputs. The DNS probe result is the right place to apply
   this transformation before it flows into the report.

---

## P9 — ARM Assessment Calls Can Trigger Subscription Throttling

### Symptom

The `--azure-assessment` flag returns `429 Too Many Requests` errors. Other ARM-dependent
automation running in the same subscription (Terraform, Azure Policy, deployment pipelines)
starts failing intermittently around the same time the tool runs.

### Root Cause

Azure Resource Manager throttles read requests at **12,000 per hour per subscription**. Running
the tool from multiple hosts simultaneously against many `--resource-id` values, or running it
on a short cron interval, can exhaust this budget and interfere with other automation.

### Fix Direction

1. **Retry with exponential backoff**: The Azure SDK's `RetryOptions` already supports this.
   Configure `MaxRetries` and `Delay` on the ARM client in
   [`AzureAssessor`](file:///src/AzureConnectivityDoctor.Core/AzureAssessment/) to handle 429
   responses gracefully without surfacing them as hard failures.

2. **Throttle assessment calls**: Add `--assessment-delay-ms <ms>` to insert a delay between
   sequential ARM reads when probing many resource IDs. Default 0ms (no change to current
   behaviour), but documented as a tuning knob.

3. **Document throttle limits** in the README so operators know to stagger scheduled runs and
   avoid running high-concurrency assessment loops.

---

## P10 — Default Concurrency Is Too Low for Large Endpoint Lists

### Symptom

Probing 50–200 endpoints with `--concurrency 4` and `--timeout 10` takes several minutes and
frequently hits the overall timeout (`--overall-timeout 300`). Some endpoints are reported as
`NotAttempted` because the overall timeout expired before they were reached.

### Root Cause

The default `MaxConcurrency` of 4 was chosen conservatively to avoid overwhelming the local
network stack. For pure I/O-bound workloads (DNS, TCP, TLS handshakes) on a well-provisioned
host, this is far too conservative — the thread pool and OS network stack can comfortably handle
16–64 concurrent connections.

### Fix Direction

1. **Raise the documented recommended concurrency** for large endpoint lists. Suggest
   `--concurrency 20` for 50–100 endpoints, `--concurrency 40` for 100+ endpoints, in the README.

2. **Smarter default**: Consider auto-scaling `MaxDegreeOfParallelism` relative to the endpoint
   count:
   ```csharp
   int defaultConcurrency = Math.Min(endpoints.Count, Math.Max(4, Environment.ProcessorCount * 4));
   ```

3. **Surface a warning finding** in the run report when `(endpoints.Count / concurrency) * timeout`
   approaches the overall timeout, so operators know to tune before hitting the limit.

---

## P11 — Default 10s Timeout Is Too Aggressive for High-Latency Paths

### Symptom

Legitimate connectivity through a VPN tunnel or cross-region private endpoint times out and is
reported as `ACD-TCP-BLOCKED`, even though the path is actually open. The operator raises a
network ticket that wastes days before someone reruns the tool with a higher timeout.

### Root Cause

The default 10-second per-stage timeout is calibrated for TCP blackhole detection (firewall
silently drops SYN packets). It is appropriate for detecting blocked ports, but too short for
legitimate high-latency paths:

| Path Type | Typical Round-Trip |
|---|---|
| Azure VNet (same region) | < 2 ms |
| ExpressRoute | 1–5 ms |
| Site-to-site VPN | 30–150 ms |
| Cross-region private endpoint | 20–80 ms |

A TLS handshake over a 150ms VPN link can legitimately take 500ms–2s. This is well within the
10s timeout, but if the VPN is momentarily congested, it can breach it.

### Fix Direction

1. **Document recommended timeout values** for different deployment contexts in the README:
   - Local / same-VNet: `--timeout 5` (fast fail)
   - VPN / ExpressRoute: `--timeout 20`
   - Cross-region / WAN: `--timeout 30`

2. **Include measured latency in the report** alongside the timeout threshold for every probe
   stage, so operators can distinguish "timed out at 10s (firewall)" from "succeeded in 8.9s
   (slow VPN — consider raising timeout)."

3. **Consider per-stage timeout flags** (`--dns-timeout`, `--tcp-timeout`, `--tls-timeout`) for
   fine-grained control without changing the blackhole-detection timeout.

---

## P12 — No Dockerfile or Env-Var Support for PaaS Deployment

### Symptom

To run this tool in Azure Container Apps, Kubernetes, or App Service WebJobs, an operator must
manually build a Docker image, figure out that all configuration is passed as CLI arguments,
and write a YAML manifest with the correct `args:` array. This is fragile and non-standard.
Operations teams will reject it in favour of tools that follow 12-factor app conventions.

### Root Cause

The tool is currently a developer CLI only. It has no `Dockerfile`, no environment-variable
configuration binding, and no published container image.

### Fix Direction

This is fully addressed by [`improvement_roadmap.md`](file:///improvement_roadmap.md) Phases 1–2.
The implementation order is:

| Priority | Roadmap Item | What It Unlocks |
|---|---|---|
| **P0** | **1.2** Self-contained single-file publish | No .NET SDK needed in container |
| **P0** | **1.1** `Dockerfile` (multi-stage, linux-x64) | Container Apps Job deployment |
| **P0** | **2.1** `ACD_*` environment variable binding | Configuration from Azure Portal / Bicep |
| **P1** | **2.2** Comma-separated `ACD_ENDPOINTS` | Endpoint list from a single App Setting |
| **P1** | **7.1** GitHub Actions Docker publish workflow | `ghcr.io/org/azure-connectivity-doctor:latest` |

Phase 1 alone (Dockerfile + env var binding) is sufficient to deploy as a Container Apps Job.
All subsequent phases add observability and durability on top.

---

## Recommended Action Order for First Enterprise Production Deployment

### Before the first run

1. **Determine the managed identity client ID** of the user-assigned MI that has RBAC roles on
   the target SQL / Service Bus resources. Pass it as `--managed-identity-client-id <GUID>`.
   Never rely on the system-assigned identity default in a multi-MI environment. → **See P1**

2. **Confirm the Azure cloud environment** (Commercial vs. Government vs. China). If the tenant
   is in Azure Government, scope URIs must be updated before identity probes will work.
   → **See P2**

3. **Capture the tool's egress IP** before adding SQL firewall rules. Run the tool once with
   `--timeout 5` and read the egress IP from the `ACD-SQL-FIREWALL` finding's evidence block,
   then provide it to the DBA team. → **See P5**

4. **Run with `--verbose`** on the first execution. Verify in the logs which credential source
   was selected and that the identity's object ID matches the expected MI in the Portal.

### Within 2 weeks of first run

5. Implement **identity self-check finding** (log OID + roles claim) — roadmap **4.2** → **P4**
6. Add **structured JSON console logging** — roadmap **3.1** → **P7**
7. Add **Blob Storage report sink** — roadmap **6.1** → **P6**
8. Add **Dockerfile + `ACD_*` env var binding** — roadmap Phase 1 → **P12**

### Within 4–6 weeks

9. **Application Insights renderer** for alerting and dashboards — roadmap **3.2** → **P7**
10. **Role pre-flight check** (warn on missing RBAC) — roadmap **4.4** → **P4**
11. **Azure Government cloud scope support** — new work → **P2**
12. **Egress IP detection at startup** — new work → **P5**

---

*Last updated: October 2026*
*Author: Azure Connectivity Doctor development team*
