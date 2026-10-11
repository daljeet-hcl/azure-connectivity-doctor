# Azure Connectivity Doctor — Testing & Quality Assurance Strategy

> **A comprehensive testing, verification, and validation guide for developers, QA engineers, and automated test pipelines.**

---

## 1. Objectives & Overview

The goal of this testing strategy is to guarantee that **Azure Connectivity Doctor** (`azure-connectivity-doctor`) performs deterministic, evidence-based diagnostic evaluation of network and cloud dependencies. 

Because this tool is used under operational pressure to triage production connectivity incidents, testing must prove beyond reasonable doubt that:
1. **Accurate Diagnosis**: The tool correctly identifies the exact failure point (DNS, TCP, TLS, Certificate, HTTP, or Entra ID / Managed Identity).
2. **Deterministic Root-Cause Codes**: The tool assigns the correct `ACD-*` identifier and actionable remediation steps.
3. **No False Positives or Cascading Errors**: Downstream stages are gated (marked `NotAttempted` or `Skipped`) rather than reporting misleading errors when an upstream stage (such as DNS) fails.
4. **Zero Secret Leakage**: Malformed inputs, connection strings, passwords, and tokens are scrubbed in memory, JSON outputs, Markdown tables, and logs.
5. **Headless & Resilient Execution**: The tool never hangs on headless agents, handles `Ctrl+C` cooperatively, and respects timeouts.

---

## 2. Four-Tier Testing Pyramid

Testing is organized into four complementary layers:

```
┌─────────────────────────────────────────────────────────────┐
│  Tier 4: Azure Cloud PaaS & Identity (Opt-In / Live Cloud)  │  <- Azure subscription + Entra ID
│  - Azure SQL TDS handshakes, Service Bus AMQP, Managed ID   │
├─────────────────────────────────────────────────────────────┤
│  Tier 3: Public Internet Failure-Mode Matrix (BadSSL, etc.) │  <- Public Internet
│  - Expired certs, untrusted roots, SAN mismatch, blackholes │
├─────────────────────────────────────────────────────────────┤
│  Tier 2: In-Process Loopback Integration Tests              │  <- Self-contained in process
│  - Ephemeral TCP listeners, resets, localhost resolution    │
├─────────────────────────────────────────────────────────────┤
│  Tier 1: Unit & Component Isolation Tests (Fakes/Stubs)     │  <- Runs in < 5s, 0 infra
│  - Parser, secret scrubber, analyzer rules, JSON/MD render  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Infrastructure & Environment Requirements

| Tier | Focus | Infrastructure Required | Execution Frequency |
|:---|:---|:---|:---|
| **Tier 1: Unit Tests** | Pure logic, rules, formatting, redaction | None (.NET 10 SDK only) | Every commit / PR build |
| **Tier 2: Loopback Tests** | Local socket handling, timeout behavior | Local OS network stack (`127.0.0.1`) | Every commit / PR build |
| **Tier 3: Live Failure Modes** | Real DNS drops, TCP blackholes, TLS flaws | Outbound Internet access (HTTP/HTTPS) | Nightly CI / Manual QA |
| **Tier 4: Azure PaaS Tests** | TDS SQL, AMQP Service Bus, Entra ID | Azure Subscription + Managed Identity | Pre-release staging / CI with Azure runner |

---

## 4. Test Suites & Execution Procedures

Three sample suites are provided in the [`samples/`](file:///samples/) directory for immediate use:

### Suite 1: Syntax & Parser Validation (`samples/test-suite-syntax-parsing.txt`)
**File Path**: [`samples/test-suite-syntax-parsing.txt`](file:///samples/test-suite-syntax-parsing.txt)

* **Objective**: Verifies that URLs with various schemes, explicit/implicit ports, IPv4/IPv6 literals, and Azure PaaS endpoints parse into correct `ProbeTarget` objects.
* **Key Targets Tested**:
  - `https://learn.microsoft.com` (Inferred port 443, HTTPS)
  - `http://example.com` (Inferred port 80, HTTP)
  - `contoso-sample.database.windows.net` (Inferred port 1433, Azure SQL)
  - `contoso-sample.servicebus.windows.net/orders` (Inferred port 5671, AMQP)
  - `[::1]:443` (IPv6 literal authority)
  - Embedded credentials (e.g., `https://user:secret@host`) &rarr; rejected and masked.
* **Execution Command**:
  ```bash
  dotnet run --project src/AzureConnectivityDoctor.Cli -- --endpoints-file samples/test-suite-syntax-parsing.txt
  ```

---

### Suite 2: Negative Connectivity & Failure Modes (`samples/test-suite-failure-modes.txt`)
**File Path**: [`samples/test-suite-failure-modes.txt`](file:///samples/test-suite-failure-modes.txt)

* **Objective**: Validates that all major network and TLS error conditions are detected and assigned the correct `ACD-*` root-cause code without throwing unhandled exceptions.
* **Test Matrix**:

| Target Tested | Failure Injected | Expected Code | Expected Diagnostic Outcome |
|:---|:---|:---:|:---|
| `this-domain-definitely-does-not-exist-acd-test-998877.org` | Non-existent domain | `ACD-DNS-NAME-NOT-FOUND` | DNS fails; TCP/TLS marked `NotAttempted`. |
| `192.0.2.1:443` (RFC 5737 TEST-NET-1) | Blackhole / dropped SYN packets | `ACD-TCP-BLOCKED` | TCP times out after specified seconds; TLS `NotAttempted`. |
| `127.0.0.1:65432` | Closed loopback port | `ACD-TCP-REFUSED` | TCP responds with `RST` / `ConnectionRefused`. |
| `https://expired.badssl.com` | Expired certificate | `ACD-CERT-EXPIRED` | TCP/TLS handshake succeeds; cert validation flags `NotTimeValid`. |
| `https://wrong.host.badssl.com` | Hostname mismatch | `ACD-CERT-NAME-MISMATCH` | Cert valid, but SAN does not match requested host. |
| `https://self-signed.badssl.com` | Self-signed / untrusted CA | `ACD-CERT-UNTRUSTED-ROOT` | Cert chain fails validation against trusted store. |
| `https://httpbin.org/status/403` | HTTP 403 response | `ACD-HTTP-403` | Tested when run with `--http`. |

* **Execution Command**:
  ```bash
  dotnet run --project src/AzureConnectivityDoctor.Cli -- --endpoints-file samples/test-suite-failure-modes.txt --timeout 3 --concurrency 2
  ```

---

### Suite 3: Azure Cloud & PaaS Scenarios (`samples/test-suite-azure-cloud.txt`)
**File Path**: [`samples/test-suite-azure-cloud.txt`](file:///samples/test-suite-azure-cloud.txt)

* **Objective**: Validates cloud-specific probes against real Azure control and data plane services.
* **Scenarios Covered**:
  1. **Azure Control Plane**: `https://management.azure.com`
  2. **Azure Entra ID Authentication**: `https://login.microsoftonline.com`
  3. **Azure SQL TDS Probe**: Tests port 1433 and SQL Server firewall responses.
  4. **Azure Service Bus AMQP**: Tests port 5671 and AMQP-over-WebSockets (port 443).
  5. **Managed Identity / Token Acquisition**: Tests token acquisition via `DefaultAzureCredential`.
* **Execution Commands**:
  ```bash
  # Test network reachability (DNS, TCP, TLS)
  dotnet run --project src/AzureConnectivityDoctor.Cli -- --endpoints-file samples/test-suite-azure-cloud.txt

  # Test authenticated probes with Managed Identity / Entra ID
  dotnet run --project src/AzureConnectivityDoctor.Cli -- --endpoints-file samples/test-suite-azure-cloud.txt --identity
  ```

---

## 5. Security & Sanitization Verification

Testers must verify that no sensitive credentials leak into outputs:
1. **URI Credentials**: `https://user:password123@api.contoso.com` &rarr; Output must read `https://user:***REDACTED***@api.contoso.com`.
2. **Connection Strings in Evidence**: Strings such as `Server=x;Password=mysecret;` must be scrubbed in both `connectivity-report.json` and `connectivity-report.md`.
3. **Automated Assertion**: Verified continuously via `ReportRendererTests.JsonRenderer_DoesNotLeakSecretsPresentInEvidence` and `DiagnosticRunnerTests.RunAsync_RecordsAFailedParseWithoutRunningAnyProbe`.

---

## 6. Continuous Integration & Automation Commands

To run the automated test suite in GitHub Actions, Azure Pipelines, or local development:

```bash
# 1. Clean and build the solution
dotnet build --configuration Release

# 2. Run unit and loopback tests (No external internet or Azure access needed)
dotnet test --configuration Release --no-build

# 3. Run opt-in live network integration tests (Requires outbound internet access)
dotnet test --configuration Release --no-build --filter Category=Integration -e ACD_INTEGRATION=1

# 4. End-to-end CLI diagnostic run on sample suites
dotnet run --project src/AzureConnectivityDoctor.Cli --configuration Release -- \
  --endpoints-file samples/test-suite-failure-modes.txt \
  --json connectivity-report.json \
  --markdown connectivity-report.md \
  --timeout 3
```

---

## 7. Quality Gate & Acceptance Criteria

A build or release is considered **valid and production-ready** if and only if:
- [x] Zero compilation warnings with `TreatWarningsAsErrors=true` in .NET 10.
- [x] 100% of unit tests pass (`AzureConnectivityDoctor.Core.Tests`).
- [x] 100% of loopback socket integration tests pass (`AzureConnectivityDoctor.IntegrationTests`).
- [x] Live failure-mode test suite accurately emits `ACD-DNS-NAME-NOT-FOUND`, `ACD-TCP-BLOCKED`, `ACD-TCP-REFUSED`, and all `ACD-CERT-*` codes.
- [x] All generated JSON and Markdown reports contain zero raw passwords, bearer tokens, or keys.
