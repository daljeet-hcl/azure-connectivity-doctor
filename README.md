# Azure Connectivity Doctor (`azure-connectivity-doctor`)

> **Evidence-based network and cloud connectivity diagnostics for .NET, Azure, and distributed enterprise workloads.**

[![.NET 10.0](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet&logoColor=white)](#prerequisites)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Cross-Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#)

---

## Executive Summary

When enterprise microservices, batch jobs, or web applications fail to connect to dependencies (databases, service buses, external APIs, private endpoints), engineers and operations teams often spend hours answering basic triage questions:
- *Is it a DNS issue?*
- *Is the firewall dropping SYN packets?*
- *Did a TLS certificate expire or fail chain validation?*
- *Is Azure Managed Identity failing to acquire an Entra ID token?*
- *Is an Azure SQL server-level firewall rule or VNet rule blocking our egress IP?*

**Azure Connectivity Doctor** is a lightweight, cross-platform diagnostic CLI tool built in **.NET 10**. It runs automated, layered network and protocol probes against target endpoints, performs automated root-cause analysis, and generates human-readable Markdown reports (for support tickets and engineering reviews) and machine-readable JSON reports (for CI/CD pipelines and automated gates).

---

## Key Features & Capabilities

- **Layered Diagnostic Pipeline**: Probes are strictly sequenced (DNS &rarr; TCP &rarr; TLS & Certificates &rarr; Protocol/Service Probes &rarr; Identity). Downstream stages are gated on prerequisite stages so readers can distinguish between *"this stage failed"* and *"this stage was never reached"*.
- **Deep Azure PaaS Support**:
  - **Azure SQL Database** (`*.database.windows.net`): TDS probe on port 1433, detecting SQL firewall blocks, VNet rule rejections, and login failures.
  - **Azure Service Bus** (`*.servicebus.windows.net`): AMQP probe on port 5671 (or AMQP-over-WebSockets on port 443), validating namespace and entity access.
  - **Private Endpoints & Azure DNS**: Detects whether PaaS hosts resolve to RFC 1918 private IPs or public IPs, pinpointing split-horizon DNS misconfigurations.
- **Certificate & TLS Inspector**: Performs real TLS handshakes, verifies certificate chains to trusted roots, checks expiration dates, flags upcoming expirations (<30 days), and checks Subject Alternative Names (SANs).
- **Security-First Architecture**:
  - Never accepts passwords, secrets, or connection strings on the command line or in endpoint files.
  - Authenticated probes exclusively use passwordless **Microsoft Entra ID** via `Azure.Identity.DefaultAzureCredential` (Managed Identity, Workload Identity, Azure CLI credentials, or environment variables).
  - Headless-friendly: Interactive browser sign-in is disabled to fail fast on headless containers, VMs, and runners.
  - All outputs and logs are sanitized against secret leakage.
- **Auditable & Automatable Reports**:
  - Outputs structured findings with deterministic error codes (e.g., `ACD-DNS-NAME-NOT-FOUND`, `ACD-TCP-BLOCKED`, `ACD-CERT-EXPIRED`, `ACD-SQL-FIREWALL`).
  - Generates both `connectivity-report.md` and `connectivity-report.json`.

---

## Architecture & How It Works

```
                                    +----------------------------------+
                                    |     User Inputs / Endpoints      |
                                    | (--endpoint / --endpoints-file)  |
                                    +-----------------+----------------+
                                                      |
                                                      v
                                    +----------------------------------+
                                    |        EndpointParser            |
                                    | (Validation & Target Type Guess) |
                                    +-----------------+----------------+
                                                      |
                                                      v
                                    +----------------------------------+
                                    |       DiagnosticRunner           |
                                    |   (Parallel Execution Engine)    |
                                    +-----------------+----------------+
                                                      |
                   +----------------------------------+----------------------------------+
                   |                                  |                                  |
                   v                                  v                                  v
         [Target 1: Web API]                [Target 2: Azure SQL]             [Target 3: Service Bus]
                   |                                  |                                  |
          1. DNS Resolution                  1. DNS Resolution                  1. DNS Resolution
                   |                                  |                                  |
          2. TCP Handshake (443)             2. TCP Handshake (1433)            2. TCP Handshake (5671)
                   |                                  |                                  |
          3. TLS & Cert Chain                3. TLS Handshake                   3. TLS Handshake
                   |                                  |                                  |
          4. HTTP Probe (GET/HEAD)           4. TDS Connection Probe            4. AMQP Link Probe
                   \                                  |                                  /
                    \                                 |                                 /
                     +--------------------------------+--------------------------------+
                                                      |
                                                      v
                                    +----------------------------------+
                                    |      Root-Cause Analyzer         |
                                    |   (Rule correlation & findings)  |
                                    +-----------------+----------------+
                                                      |
                                                      v
                                    +----------------------------------+
                                    |         Report Generation        |
                                    |  * connectivity-report.md        |
                                    |  * connectivity-report.json      |
                                    +----------------------------------+
```

### The 5 Diagnostic Stages

| Stage | Name | Description |
|:---:|:---|:---|
| **1** | **DNS Probe** | Resolves hostnames to IPv4/IPv6 addresses. Distinguishes between Public IPs, RFC 1918 Private IPs (Private Endpoints), and Loopback addresses. |
| **2** | **TCP Probe** | Tests raw TCP connectivity against the target port. Distinguishes between timeouts (silent packet drop / firewall) and connection refused (`RST` / no service listening). |
| **3** | **TLS Probe** | Executes a TLS handshake and evaluates certificates (validity period, root trust, SAN match, expiration warnings). |
| **4** | **Service Probe** | Protocol-level handshake based on the target type:<br>&bull; **HTTP(S)**: Verifies response codes and proxy requirements.<br>&bull; **Azure SQL**: Verifies TDS handshake and server firewall response.<br>&bull; **Azure Service Bus**: Tests AMQP connection and entity reachability. |
| **5** | **Identity Probe** *(Optional)* | Uses `DefaultAzureCredential` to acquire Entra ID tokens for Azure services without passwords or client secrets. |

---

## Supported Endpoint Formats

Endpoints can be supplied on the command line or inside a text file (one endpoint per line, `#` comments ignored):

| Target Type | Example | Inferred Default Port |
|:---|:---|:---:|
| **HTTPS / Web API** | `https://api.contoso.com/health` | `443` |
| **HTTP Web Service** | `http://intranet.contoso.internal` | `80` |
| **Azure SQL Server** | `mydbserver.database.windows.net` | `1433` |
| **Azure SQL with DB** | `mydbserver.database.windows.net/ordersdb` | `1433` |
| **Azure Service Bus** | `mybus.servicebus.windows.net` | `5671` (AMQP) |
| **Service Bus over WebSockets** | `mybus.servicebus.windows.net:443` | `443` |
| **Explicit Host & Port** | `10.0.1.4:8443` | `8443` |
| **IPv6 Literal** | `[2603:1010::1]:443` | `443` |

---

## CLI Usage & Options

### Basic Command Syntax

```bash
azure-connectivity-doctor <endpoint> [<endpoint> ...] [options]
```

### Key Options

```text
--endpoint <target>       Target endpoint (may be specified multiple times).
--endpoints-file <path>   Path to a text file listing endpoints (one per line).
--timeout <seconds>       Per-stage timeout in seconds (Default: 10s).
--overall-timeout <sec>   Total execution time budget for the entire run (Default: 300s).
--concurrency <count>     Number of endpoints probed in parallel (Default: 4).
--http                    Sends a real HTTP request for HTTP/HTTPS endpoints.
--identity                Enables Microsoft Entra ID token acquisition for authenticated tests.
--azure-assessment        Queries read-only Azure Resource Manager (ARM) metadata.
--resource-id <id>        Azure resource ID for assessment (can be repeated).
--tenant-id <id>          Restricts Entra ID token acquisition to a specific tenant.
--client-id <id>          Specifies client ID of a User-Assigned Managed Identity.
--markdown <path>         Path for the Markdown report (Default: connectivity-report.md).
--no-markdown             Disables writing the Markdown report.
--json <path>             Path for the JSON report (Default: connectivity-report.json).
--no-json                 Disables writing the JSON report.
--quiet                   Suppresses printing the Markdown report to stdout.
--verbose                 Enables debug-level diagnostic logs.
```

### Exit Codes

| Code | Meaning | Use Case |
|:---:|:---|:---|
| `0` | **Success** | All probes succeeded; no error-severity findings detected. |
| `1` | **Diagnostic Failure** | At least one endpoint reported an error-level connectivity issue. |
| `2` | **Usage Error** | Invalid command-line arguments or endpoint format. |
| `3` | **Cancelled** | Run was cancelled via Ctrl+C or exceeded overall timeout. |
| `4` | **Internal Error** | Unexpected exception encountered. |

---

## Example Scenarios

### 1. Diagnose an Outbound Web API Dependency
```bash
azure-connectivity-doctor https://api.partner.com/v1/health --http
```

### 2. Verify Azure SQL Connectivity with Managed Identity
```bash
azure-connectivity-doctor contosodb.database.windows.net/sales --identity
```

### 3. Bulk Triage from a Workload Manifest
```bash
azure-connectivity-doctor --endpoints-file samples/endpoints.txt --json report.json --markdown report.md
```

### 4. Headless Execution in CI/CD or Kubernetes Startup Probe
```bash
azure-connectivity-doctor \
  --endpoints-file /etc/config/endpoints.txt \
  --quiet \
  --json /var/log/connectivity.json
```

---

## Sample Diagnostic Report (`connectivity-report.md`)

```markdown
# Connectivity Diagnostic Report
Generated: 2026-10-11T17:15:00Z | Host: agent-node-04 | Platform: Linux x64

## Summary
- Endpoints Tested: 3
- Healthy: 2
- Errors Found: 1

## Findings

| Code | Severity | Target | Message | Recommendation |
|:---|:---:|:---|:---|:---|
| `ACD-TCP-BLOCKED` | **Error** | `contosodb.database.windows.net:1433` | TCP connection timed out after 10000ms. DNS resolved to `10.200.1.5`. | The DNS name resolved to a private endpoint IP, but TCP SYN packets are not getting a response. Verify NSG rules on the subnet and route table routing to the private endpoint. |

## Stage Results

| Target | DNS | TCP | TLS | Service | Identity |
|:---|:---:|:---:|:---:|:---:|:---:|
| `https://api.github.com` | Passed | Passed | Passed | Passed (HTTP 200) | Skipped |
| `contosodb.database.windows.net` | Passed | Failed | Not Attempted | Not Attempted | Not Attempted |
| `orders.servicebus.windows.net` | Passed | Passed | Passed | Passed (AMQP) | Passed |
```

---

## Diagnostic Finding Codes

The root-cause engine assigns deterministic codes to findings so alerting, monitoring systems, and ticket workflows can parse and automate responses:

- **DNS**: `ACD-DNS-NAME-NOT-FOUND`, `ACD-DNS-TIMEOUT`, `ACD-PRIVATE-ENDPOINT-DNS`, `ACD-PUBLIC-DNS-BUT-BLOCKED`
- **TCP**: `ACD-TCP-BLOCKED`, `ACD-TCP-REFUSED`, `ACD-TCP-UNREACHABLE`
- **TLS & Certificates**: `ACD-TLS-HANDSHAKE-FAILED`, `ACD-CERT-NAME-MISMATCH`, `ACD-CERT-EXPIRED`, `ACD-CERT-EXPIRING-SOON`, `ACD-CERT-UNTRUSTED-ROOT`
- **HTTP**: `ACD-HTTP-403`, `ACD-HTTP-PROXY-AUTH`, `ACD-PROXY-CONFIGURED`
- **Azure Identity**: `ACD-IDENTITY-UNAVAILABLE`, `ACD-IDENTITY-REJECTED`
- **Azure SQL**: `ACD-SQL-FIREWALL`, `ACD-SQL-VNET-RULE`, `ACD-SQL-LOGIN-DENIED`, `ACD-SQL-DATABASE-UNAVAILABLE`
- **Azure Service Bus**: `ACD-SB-UNAUTHORIZED`, `ACD-SB-ENTITY-NOT-FOUND`, `ACD-SB-AMQP-BLOCKED`

---

## Building and Testing

### Prerequisites
- [.NET 10.0 SDK](https://dotnet.microsoft.com/download)

### Build Solution
```bash
dotnet build
```

### Run Tests
```bash
# Run unit and core tests
dotnet test

# Run network integration tests (requires network access)
dotnet test --filter Category=Integration -e ACD_INTEGRATION=1
```

---

## Contributing & Development Roadmap
- [x] Fix Windows localhost DNS IP resolution in `DnsProbe`.
- [x] Ensure end-to-end secret scrubbing in malformed target inputs and evidence dictionaries.
- [ ] Add support for automated discovery of dependency endpoints directly by scanning `.csproj` / `appsettings.json` configurations.
