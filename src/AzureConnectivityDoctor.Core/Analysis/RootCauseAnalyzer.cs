using System.Globalization;
using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Analysis;

/// <summary>
/// Correlates stage results into findings.
/// </summary>
/// <remarks>
/// <para>
/// The analyzer is a pure function of the stage results. It performs no input and output of
/// its own, which is what makes it exhaustively unit-testable: a test constructs the stage
/// results it wants to reason about and asserts on the findings, with no network involved.
/// </para>
/// <para>
/// Every rule is expressed as "this observation, combined with that observation, implies this
/// conclusion", and each finding carries the stages it was derived from together with an
/// explicit <see cref="EvidenceConfidence"/>. Rules never overwrite one another; several
/// findings may be emitted for one target and are returned most severe first.
/// </para>
/// </remarks>
public sealed class RootCauseAnalyzer : IRootCauseAnalyzer
{
    /// <summary>Certificates closer than this to expiry produce a warning.</summary>
    public const int CertificateExpiryWarningDays = 30;

    /// <inheritdoc />
    public IReadOnlyList<Finding> Analyze(
        ProbeTarget? target,
        IReadOnlyList<StageResult> stages,
        IReadOnlyList<StageResult> azureAssessment)
    {
        ArgumentNullException.ThrowIfNull(stages);
        ArgumentNullException.ThrowIfNull(azureAssessment);

        var findings = new List<Finding>();

        AddParsingFindings(stages, findings);
        AddDnsFindings(stages, findings);
        AddTcpFindings(target, stages, findings);
        AddTlsFindings(stages, findings);
        AddCertificateFindings(stages, findings);
        AddHttpFindings(stages, findings);
        AddIdentityFindings(stages, findings);
        AddSqlFindings(stages, findings);
        AddServiceBusFindings(stages, findings);
        AddAzureAssessmentFindings(target, stages, azureAssessment, findings);

        if (!findings.Exists(finding => finding.Severity != FindingSeverity.Information))
        {
            findings.Add(BuildHealthyFinding(stages));
        }

        return [.. findings.OrderByDescending(finding => finding.Severity).ThenBy(finding => finding.Code, StringComparer.Ordinal)];
    }

    private static void AddParsingFindings(IReadOnlyList<StageResult> stages, List<Finding> findings)
    {
        StageResult? parsing = Find(stages, DiagnosticStage.EndpointParsing);
        if (parsing is null || parsing.Outcome != DiagnosticOutcome.Failed)
        {
            return;
        }

        findings.Add(new Finding
        {
            Code = FindingCodes.ParseFailed,
            Title = "The endpoint could not be parsed",
            Severity = FindingSeverity.Error,
            Confidence = EvidenceConfidence.Observed,
            Rationale = parsing.Summary,
            BasedOnStages = [DiagnosticStage.EndpointParsing],
            RecommendedActions =
            [
                "Supply the endpoint as 'host', 'host:port' or 'scheme://host:port/path'.",
                "Use '[address]:port' for IPv6 literals.",
                "Never embed credentials in the endpoint; pass identity through a credential source instead."
            ]
        });
    }

    private static void AddDnsFindings(IReadOnlyList<StageResult> stages, List<Finding> findings)
    {
        StageResult? dns = Find(stages, DiagnosticStage.DnsResolution);
        if (dns is null)
        {
            return;
        }

        if (dns.Outcome == DiagnosticOutcome.Failed)
        {
            string socketError = Evidence(dns, "socketError");

            if (string.Equals(socketError, "HostNotFound", StringComparison.Ordinal))
            {
                findings.Add(new Finding
                {
                    Code = FindingCodes.DnsNameNotFound,
                    Title = "The host name does not exist for this resolver",
                    Severity = FindingSeverity.Error,
                    Confidence = EvidenceConfidence.Observed,
                    Rationale =
                        "The resolver answered authoritatively that the name does not exist. The resolver " +
                        "itself is therefore reachable and working, so this is a naming or DNS-zone problem " +
                        "rather than a network-path problem.",
                    BasedOnStages = [DiagnosticStage.DnsResolution],
                    RecommendedActions =
                    [
                        "Check the host name for a typo.",
                        "If the name is served by an Azure private DNS zone, confirm the zone is linked to " +
                        "the virtual network this workload runs in.",
                        "On Azure App Service, confirm virtual network integration is enabled when the name " +
                        "is private."
                    ]
                });
            }
            else if (string.Equals(dns.ErrorType, nameof(TimeoutException), StringComparison.Ordinal))
            {
                findings.Add(new Finding
                {
                    Code = FindingCodes.DnsTimeout,
                    Title = "The DNS resolver did not answer",
                    Severity = FindingSeverity.Error,
                    Confidence = EvidenceConfidence.Observed,
                    Rationale =
                        "No answer of any kind arrived before the timeout. A silent resolver points at an " +
                        "unreachable or misconfigured DNS server, not at a wrong host name.",
                    BasedOnStages = [DiagnosticStage.DnsResolution],
                    RecommendedActions =
                    [
                        "Confirm the configured DNS servers are reachable from this workload.",
                        "In a container, inspect the resolver configuration injected by the platform.",
                        "If a custom DNS server is set on the virtual network, confirm UDP and TCP port 53 " +
                        "are permitted to it."
                    ]
                });
            }
            else
            {
                findings.Add(new Finding
                {
                    Code = FindingCodes.DnsFailed,
                    Title = "Name resolution failed",
                    Severity = FindingSeverity.Error,
                    Confidence = EvidenceConfidence.Observed,
                    Rationale = dns.Summary,
                    BasedOnStages = [DiagnosticStage.DnsResolution],
                    RecommendedActions =
                    [
                        "Review the reported socket error.",
                        "Confirm the workload has a working DNS configuration."
                    ]
                });
            }

            return;
        }

        if (dns.Outcome != DiagnosticOutcome.Succeeded)
        {
            return;
        }

        bool allPrivate = Flag(dns, "allAddressesPrivate");
        bool azurePaas = Flag(dns, "hostLooksLikeAzurePaas");

        if (allPrivate && azurePaas)
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.PrivateEndpointDns,
                Title = "The Azure service resolves to a private address",
                Severity = FindingSeverity.Information,
                Confidence = EvidenceConfidence.Inferred,
                Rationale =
                    "An Azure PaaS host name resolved only to addresses in private ranges. That is the " +
                    "expected result when a private endpoint and its private DNS zone are in use. This is " +
                    "inferred rather than observed: the managed resolver API returns addresses only, so the " +
                    "'privatelink' alias in the CNAME chain cannot be seen directly.",
                BasedOnStages = [DiagnosticStage.DnsResolution],
                RecommendedActions =
                [
                    "No action is required if a private endpoint is intended.",
                    "If public access was intended, the private DNS zone is overriding the public record."
                ]
            });
        }
    }

    private static void AddTcpFindings(
        ProbeTarget? target,
        IReadOnlyList<StageResult> stages,
        List<Finding> findings)
    {
        StageResult? tcp = Find(stages, DiagnosticStage.TcpConnect);
        if (tcp is null || tcp.Outcome != DiagnosticOutcome.Failed)
        {
            return;
        }

        string socketError = Evidence(tcp, "socketError");
        StageResult? dns = Find(stages, DiagnosticStage.DnsResolution);
        int port = target?.Port ?? 0;

        if (string.Equals(socketError, "TimedOut", StringComparison.Ordinal))
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.TcpBlocked,
                Title = "Outbound traffic on this port is being dropped",
                Severity = FindingSeverity.Error,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "The connection attempt received no reply at all. A device in the path is discarding " +
                    "packets silently. A closed port would have produced an immediate refusal instead, so " +
                    "this is a packet filter rather than an absent listener.",
                BasedOnStages = [DiagnosticStage.DnsResolution, DiagnosticStage.TcpConnect],
                RecommendedActions =
                [
                    string.Create(
                        CultureInfo.InvariantCulture,
                        $"Check outbound network security group and firewall rules for TCP port {port}."),
                    "Check the target service's own firewall, virtual network rules and public network access setting.",
                    "If the workload routes through a network virtual appliance or forced tunnel, confirm the " +
                    "appliance permits this destination.",
                    "On Azure App Service, confirm virtual network integration and route-all settings match the " +
                    "intended path."
                ]
            });

            if (dns is not null
                && dns.Outcome == DiagnosticOutcome.Succeeded
                && Flag(dns, "hostLooksLikeAzurePaas")
                && !Flag(dns, "allAddressesPrivate"))
            {
                findings.Add(new Finding
                {
                    Code = FindingCodes.PublicDnsButBlocked,
                    Title = "The Azure service resolves publicly but does not accept the connection",
                    Severity = FindingSeverity.Error,
                    Confidence = EvidenceConfidence.Inferred,
                    Rationale =
                        "The host resolved to a public address and the connection was then dropped. When a " +
                        "service has public network access disabled, or the caller's address is outside its " +
                        "allow list, the platform drops the packets exactly like this. If a private endpoint " +
                        "exists, the public answer also means the private DNS zone is not being used by this " +
                        "workload.",
                    BasedOnStages = [DiagnosticStage.DnsResolution, DiagnosticStage.TcpConnect],
                    RecommendedActions =
                    [
                        "Re-run with the Azure assessment enabled and the resource ID supplied to read the " +
                        "service's public network access setting directly.",
                        "If a private endpoint exists, link its private DNS zone to this workload's virtual network.",
                        "Otherwise add the caller's outbound address to the service firewall."
                    ]
                });
            }

            return;
        }

        if (string.Equals(socketError, "ConnectionRefused", StringComparison.Ordinal))
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.TcpRefused,
                Title = "The connection was actively refused",
                Severity = FindingSeverity.Error,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "The destination replied with a reset. The network path is healthy end to end; nothing is " +
                    "listening on that port. This is a service or port problem, not a firewall problem.",
                BasedOnStages = [DiagnosticStage.TcpConnect],
                RecommendedActions =
                [
                    "Confirm the port number is correct for the service.",
                    "Confirm the target service is running and bound to the expected interface."
                ]
            });
            return;
        }

        if (string.Equals(socketError, "NetworkUnreachable", StringComparison.Ordinal)
            || string.Equals(socketError, "HostUnreachable", StringComparison.Ordinal))
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.TcpUnreachable,
                Title = "No route to the destination",
                Severity = FindingSeverity.Error,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "The local network stack has no usable route to the resolved address. This fails before " +
                    "any packet leaves the host.",
                BasedOnStages = [DiagnosticStage.TcpConnect],
                RecommendedActions =
                [
                    "Check the effective route table for the subnet.",
                    "If the address is private, confirm the workload is joined to the correct virtual network.",
                    "If the resolved address is IPv6, confirm the environment has IPv6 connectivity."
                ]
            });
            return;
        }

        findings.Add(new Finding
        {
            Code = FindingCodes.TcpFailed,
            Title = "The TCP connection failed",
            Severity = FindingSeverity.Error,
            Confidence = EvidenceConfidence.Observed,
            Rationale = tcp.Summary,
            BasedOnStages = [DiagnosticStage.TcpConnect],
            RecommendedActions = ["Review the reported socket error and the per-address attempt list."]
        });
    }

    private static void AddTlsFindings(IReadOnlyList<StageResult> stages, List<Finding> findings)
    {
        StageResult? tls = Find(stages, DiagnosticStage.TlsHandshake);
        StageResult? tcp = Find(stages, DiagnosticStage.TcpConnect);

        if (tls is null
            || tls.Outcome != DiagnosticOutcome.Failed
            || tcp is null
            || tcp.Outcome != DiagnosticOutcome.Succeeded)
        {
            return;
        }

        findings.Add(new Finding
        {
            Code = FindingCodes.TlsHandshakeFailed,
            Title = "TCP succeeded but TLS did not",
            Severity = FindingSeverity.Error,
            Confidence = EvidenceConfidence.Observed,
            Rationale =
                "The transport is fine and the failure is in the TLS negotiation itself. The usual causes are " +
                "a protocol or cipher mismatch, a service that requires a newer TLS version than the client " +
                "offers, or a device terminating TLS in the middle of the path.",
            BasedOnStages = [DiagnosticStage.TcpConnect, DiagnosticStage.TlsHandshake],
            RecommendedActions =
            [
                "Confirm the service's minimum TLS version and that the client platform supports it.",
                "Check whether an inspecting proxy or network virtual appliance terminates TLS on this path.",
                "Confirm the endpoint really speaks TLS immediately on connect; some protocols upgrade later."
            ]
        });
    }

    private static void AddCertificateFindings(IReadOnlyList<StageResult> stages, List<Finding> findings)
    {
        StageResult? certificate = Find(stages, DiagnosticStage.CertificateValidation);
        if (certificate is null)
        {
            return;
        }

        if (certificate.Outcome == DiagnosticOutcome.Succeeded)
        {
            string daysText = Evidence(certificate, "daysUntilExpiry");
            if (double.TryParse(daysText, NumberStyles.Float, CultureInfo.InvariantCulture, out double days)
                && days is >= 0 and < CertificateExpiryWarningDays)
            {
                findings.Add(new Finding
                {
                    Code = FindingCodes.CertificateExpiringSoon,
                    Title = "The server certificate expires soon",
                    Severity = FindingSeverity.Warning,
                    Confidence = EvidenceConfidence.Observed,
                    Rationale = string.Create(
                        CultureInfo.InvariantCulture,
                        $"The certificate is valid now but expires in {days:F1} day(s)."),
                    BasedOnStages = [DiagnosticStage.CertificateValidation],
                    RecommendedActions = ["Renew or rotate the certificate before it expires."]
                });
            }

            return;
        }

        if (certificate.Outcome != DiagnosticOutcome.Failed)
        {
            return;
        }

        string chainStatus = Evidence(certificate, "chainStatus");
        bool nameMatches = Flag(certificate, "hostNameMatchesCertificate");
        bool currentlyValid = Flag(certificate, "isCurrentlyValid");

        if (!currentlyValid)
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.CertificateExpired,
                Title = "The server certificate is not currently valid",
                Severity = FindingSeverity.Error,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "The current time is outside the certificate's validity window. Note that a client clock " +
                    "that is badly wrong produces the same symptom, so verify the local time as well.",
                BasedOnStages = [DiagnosticStage.CertificateValidation],
                RecommendedActions =
                [
                    "Renew the server certificate.",
                    "Confirm the client clock is synchronised."
                ]
            });
        }

        if (!nameMatches)
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.CertificateNameMismatch,
                Title = "The certificate does not cover the requested host name",
                Severity = FindingSeverity.Error,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "None of the certificate's subject alternative names matches the requested host name. " +
                    "This happens when a shared front end serves the connection, when a custom domain is not " +
                    "bound to a certificate, or when the connection reached the wrong service.",
                BasedOnStages = [DiagnosticStage.CertificateValidation],
                RecommendedActions =
                [
                    "Bind a certificate that includes the requested host name.",
                    "Compare the reported subject alternative names with the host name that was requested."
                ]
            });
        }

        if (chainStatus.Contains("UntrustedRoot", StringComparison.Ordinal)
            || chainStatus.Contains("PartialChain", StringComparison.Ordinal))
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.CertificateUntrustedRoot,
                Title = "The certificate chain does not reach a trusted root",
                Severity = FindingSeverity.Error,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "The chain terminates in a root the client does not trust, or the server did not send the " +
                    "intermediate certificates. On a path through a corporate proxy this is the signature of " +
                    "TLS inspection: the proxy re-signs traffic with its own certificate authority.",
                BasedOnStages = [DiagnosticStage.CertificateValidation],
                RecommendedActions =
                [
                    "Compare the reported issuer with the service's real issuer; an unfamiliar issuer indicates " +
                    "TLS interception.",
                    "If interception is intended, install the inspecting authority's root certificate in the " +
                    "container or host trust store.",
                    "If it is not intended, exclude this destination from inspection.",
                    "If the chain is partial, configure the server to send its intermediate certificates."
                ]
            });
        }

        if (currentlyValid && nameMatches && chainStatus.Length > 0
            && !chainStatus.Contains("UntrustedRoot", StringComparison.Ordinal)
            && !chainStatus.Contains("PartialChain", StringComparison.Ordinal))
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.CertificateInvalid,
                Title = "The server certificate failed validation",
                Severity = FindingSeverity.Error,
                Confidence = EvidenceConfidence.Observed,
                Rationale = certificate.Summary,
                BasedOnStages = [DiagnosticStage.CertificateValidation],
                RecommendedActions = ["Review the reported chain status and policy errors."]
            });
        }
    }

    private static void AddHttpFindings(IReadOnlyList<StageResult> stages, List<Finding> findings)
    {
        StageResult? http = Find(stages, DiagnosticStage.HttpRequest);
        if (http is null)
        {
            return;
        }

        if (http.Evidence.Keys.Any(key => key.StartsWith("proxy.", StringComparison.Ordinal)))
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.ProxyConfigured,
                Title = "An HTTP proxy is configured in this environment",
                Severity = FindingSeverity.Information,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "Proxy environment variables are set, so outbound HTTP traffic from this process is not " +
                    "going directly to the destination. This changes the meaning of every HTTP and TLS result " +
                    "below.",
                BasedOnStages = [DiagnosticStage.HttpRequest],
                RecommendedActions =
                [
                    "Confirm the proxy is intended.",
                    "If the destination should bypass the proxy, add it to the no-proxy list."
                ]
            });
        }

        string statusText = Evidence(http, "statusCode");
        if (!int.TryParse(statusText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int status))
        {
            return;
        }

        if (status == 403)
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.Http403,
                Title = "The service returned 403 Forbidden",
                Severity = FindingSeverity.Warning,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "The request reached the service, so the network path, TLS and DNS are all healthy. The " +
                    "service itself rejected the caller. For Azure PaaS this is frequently an IP restriction " +
                    "or a disabled public network access setting rather than an application authorisation " +
                    "failure.",
                BasedOnStages = [DiagnosticStage.HttpRequest],
                RecommendedActions =
                [
                    "Check the service's network access restrictions for the caller's outbound address.",
                    "Check whether authentication was required and not supplied."
                ]
            });
        }
        else if (status == 407)
        {
            findings.Add(new Finding
            {
                Code = FindingCodes.HttpProxyAuthenticationRequired,
                Title = "The proxy requires authentication",
                Severity = FindingSeverity.Error,
                Confidence = EvidenceConfidence.Observed,
                Rationale =
                    "An intermediate proxy demanded credentials. The request never reached the destination " +
                    "service.",
                BasedOnStages = [DiagnosticStage.HttpRequest],
                RecommendedActions =
                [
                    "Supply proxy credentials through the platform's standard proxy configuration.",
                    "Or exempt this destination from the proxy."
                ]
            });
        }
    }

    private static void AddIdentityFindings(IReadOnlyList<StageResult> stages, List<Finding> findings)
    {
        StageResult? identity = Find(stages, DiagnosticStage.IdentityTokenAcquisition);
        if (identity is null || identity.Outcome != DiagnosticOutcome.Failed)
        {
            return;
        }

        bool unavailable = string.Equals(
            identity.ErrorType,
            "CredentialUnavailableException",
            StringComparison.Ordinal);

        findings.Add(new Finding
        {
            Code = unavailable ? FindingCodes.IdentityUnavailable : FindingCodes.IdentityRejected,
            Title = unavailable
                ? "No credential source was available"
                : "The token request was rejected",
            Severity = FindingSeverity.Error,
            Confidence = EvidenceConfidence.Observed,
            Rationale = unavailable
                ? "The credential chain found nothing it could use. This is an environment configuration " +
                  "problem, not a network problem, and it blocks every authenticated probe."
                : "A credential source was found, but the identity provider refused to issue a token for the " +
                  "requested scope. The network path to the identity provider is therefore working.",
            BasedOnStages = [DiagnosticStage.IdentityTokenAcquisition],
            RecommendedActions = unavailable
                ?
                [
                    "On Azure App Service or Azure Container Apps, enable a managed identity.",
                    "In Kubernetes, configure workload identity.",
                    "On a workstation, sign in with a supported developer credential.",
                    "In CI, configure workload identity federation."
                ]
                :
                [
                    "Confirm the identity exists in the expected tenant.",
                    "Confirm the identity is granted access to the target resource.",
                    "If a user-assigned identity is intended, supply its client ID."
                ]
        });
    }

    private static void AddSqlFindings(IReadOnlyList<StageResult> stages, List<Finding> findings)
    {
        StageResult? sql = Find(stages, DiagnosticStage.SqlConnection);
        if (sql is null || sql.Outcome != DiagnosticOutcome.Failed)
        {
            return;
        }

        string interpretation = Evidence(sql, "interpretation");
        string numberText = Evidence(sql, "sqlErrorNumber");
        _ = int.TryParse(numberText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int number);

        (string code, string title, string[] actions) = number switch
        {
            40615 =>
            (
                FindingCodes.SqlFirewall,
                "The Azure SQL server firewall rejected the caller",
                new[]
                {
                    "Add a firewall rule for the caller's outbound address on the logical server.",
                    "Or enable 'Allow Azure services and resources to access this server' if that matches policy.",
                    "Or connect through a private endpoint."
                }
            ),
            40914 =>
            (
                FindingCodes.SqlVirtualNetworkRule,
                "A virtual network rule rejected the connection",
                new[]
                {
                    "Add a virtual network rule for the caller's subnet on the logical server.",
                    "Confirm the Microsoft.Sql service endpoint is enabled on that subnet."
                }
            ),
            18456 =>
            (
                FindingCodes.SqlLoginDenied,
                "The Azure SQL login was rejected",
                new[]
                {
                    "Create a contained database user for the identity with CREATE USER [name] FROM EXTERNAL PROVIDER.",
                    "Grant that user the roles it needs.",
                    "Confirm the token was issued for the correct tenant."
                }
            ),
            4060 or 40532 =>
            (
                FindingCodes.SqlDatabaseUnavailable,
                "The requested database could not be opened",
                new[]
                {
                    "Confirm the database name.",
                    "Confirm the identity has permission on that database."
                }
            ),
            _ =>
            (
                FindingCodes.SqlFailed,
                "The Azure SQL connection failed",
                new[] { "Review the reported server error number and message." }
            )
        };

        findings.Add(new Finding
        {
            Code = code,
            Title = title,
            Severity = FindingSeverity.Error,
            Confidence = EvidenceConfidence.Observed,
            Rationale = interpretation.Length > 0 ? interpretation : sql.Summary,
            BasedOnStages = [DiagnosticStage.TcpConnect, DiagnosticStage.SqlConnection],
            RecommendedActions = actions
        });
    }

    private static void AddServiceBusFindings(IReadOnlyList<StageResult> stages, List<Finding> findings)
    {
        StageResult? serviceBus = Find(stages, DiagnosticStage.ServiceBusLink);
        if (serviceBus is null || serviceBus.Outcome != DiagnosticOutcome.Failed)
        {
            return;
        }

        string reason = Evidence(serviceBus, "failureReason");

        (string code, string title, string[] actions) = reason switch
        {
            "Unauthorized" =>
            (
                FindingCodes.ServiceBusUnauthorized,
                "The identity is not authorised on the Service Bus entity",
                new[]
                {
                    "Assign the Azure Service Bus Data Sender role at the namespace or entity scope.",
                    "Allow a few minutes for the role assignment to propagate."
                }
            ),
            "MessagingEntityNotFound" =>
            (
                FindingCodes.ServiceBusEntityNotFound,
                "The Service Bus queue or topic does not exist",
                new[]
                {
                    "Check the entity name.",
                    "Confirm the entity exists in this namespace rather than another environment's namespace."
                }
            ),
            "ServiceCommunicationProblem" or "ServiceTimeout" =>
            (
                FindingCodes.ServiceBusAmqpBlocked,
                "The AMQP port appears to be blocked",
                new[]
                {
                    "Allow outbound TCP port 5671, or switch the client to AMQP over WebSockets on port 443.",
                    "Re-run this tool with the WebSockets transport to confirm the diagnosis.",
                    "Check the namespace's public network access setting and IP filter rules."
                }
            ),
            _ =>
            (
                FindingCodes.ServiceBusFailed,
                "The Service Bus link failed",
                new[] { "Review the reported failure reason and message." }
            )
        };

        findings.Add(new Finding
        {
            Code = code,
            Title = title,
            Severity = FindingSeverity.Error,
            Confidence = EvidenceConfidence.Observed,
            Rationale = Evidence(serviceBus, "interpretation") is { Length: > 0 } text
                ? text
                : serviceBus.Summary,
            BasedOnStages = [DiagnosticStage.TcpConnect, DiagnosticStage.ServiceBusLink],
            RecommendedActions = actions
        });
    }

    private static void AddAzureAssessmentFindings(
        ProbeTarget? target,
        IReadOnlyList<StageResult> stages,
        IReadOnlyList<StageResult> azureAssessment,
        List<Finding> findings)
    {
        if (target is null || azureAssessment.Count == 0)
        {
            return;
        }

        string firstLabel = target.Host.Split('.')[0];

        foreach (StageResult assessment in azureAssessment)
        {
            if (assessment.Outcome != DiagnosticOutcome.Succeeded)
            {
                continue;
            }

            if (!string.Equals(Evidence(assessment, "resourceName"), firstLabel, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string publicAccess = Evidence(assessment, "publicNetworkAccess");
            if (!string.Equals(publicAccess, "Disabled", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string connectionCountText = Evidence(assessment, "privateEndpointConnectionCount");
            bool hasConnectionCount = int.TryParse(
                connectionCountText,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out int connectionCount);

            if (hasConnectionCount && connectionCount == 0)
            {
                findings.Add(new Finding
                {
                    Code = FindingCodes.AzureNoIngressPath,
                    Title = "The resource has no reachable ingress path",
                    Severity = FindingSeverity.Error,
                    Confidence = EvidenceConfidence.Verified,
                    Rationale =
                        "Azure Resource Manager reports that public network access is disabled and that no " +
                        "private endpoint connection exists. No client can reach this resource until one of " +
                        "those two facts changes. This was read from the Azure control plane, not inferred.",
                    BasedOnStages = [DiagnosticStage.AzureResourceAssessment],
                    RecommendedActions =
                    [
                        "Create a private endpoint for the resource in the caller's virtual network, and link " +
                        "its private DNS zone.",
                        "Or re-enable public network access with an appropriate firewall allow list."
                    ]
                });
                continue;
            }

            StageResult? dns = Find(stages, DiagnosticStage.DnsResolution);
            if (dns is not null && dns.Outcome == DiagnosticOutcome.Succeeded && !Flag(dns, "allAddressesPrivate"))
            {
                findings.Add(new Finding
                {
                    Code = FindingCodes.AzurePrivateDnsMissing,
                    Title = "Public access is disabled but this workload still resolves the public address",
                    Severity = FindingSeverity.Error,
                    Confidence = EvidenceConfidence.Verified,
                    Rationale =
                        "Azure Resource Manager reports public network access is disabled and a private " +
                        "endpoint exists, yet name resolution in this workload returned a public address. The " +
                        "private DNS zone is not reaching this workload's resolver, so traffic is being sent " +
                        "to an address that will never answer.",
                    BasedOnStages = [DiagnosticStage.DnsResolution, DiagnosticStage.AzureResourceAssessment],
                    RecommendedActions =
                    [
                        "Link the resource's privatelink DNS zone to the virtual network this workload runs in.",
                        "On Azure App Service, enable virtual network integration and route outbound traffic " +
                        "through it so the private zone applies.",
                        "Confirm no custom DNS server is answering the privatelink name with the public record."
                    ]
                });
            }
        }
    }

    private static Finding BuildHealthyFinding(IReadOnlyList<StageResult> stages)
    {
        var succeeded = new List<DiagnosticStage>();
        foreach (StageResult stage in stages)
        {
            if (stage.Outcome == DiagnosticOutcome.Succeeded)
            {
                succeeded.Add(stage.Stage);
            }
        }

        return new Finding
        {
            Code = FindingCodes.NoIssueDetected,
            Title = "No connectivity problem was detected",
            Severity = FindingSeverity.Information,
            Confidence = EvidenceConfidence.Observed,
            Rationale = succeeded.Count == 0
                ? "No stage reported a failure, but no stage produced a positive result either. Treat this " +
                  "run as inconclusive rather than healthy."
                : "Every stage that ran completed successfully from this environment, at this moment. This " +
                  "says nothing about other environments or other times.",
            BasedOnStages = succeeded,
            RecommendedActions = []
        };
    }

    private static StageResult? Find(IReadOnlyList<StageResult> stages, DiagnosticStage stage)
    {
        foreach (StageResult result in stages)
        {
            if (result.Stage == stage)
            {
                return result;
            }
        }

        return null;
    }

    private static string Evidence(StageResult stage, string key)
    {
        return stage.Evidence.TryGetValue(key, out string? value) ? value : string.Empty;
    }

    private static bool Flag(StageResult stage, string key)
    {
        return string.Equals(Evidence(stage, key), bool.TrueString, StringComparison.OrdinalIgnoreCase);
    }
}
