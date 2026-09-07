using System.Globalization;
using System.Net;
using System.Reflection;
using AzureConnectivityDoctor.Core.Analysis;
using AzureConnectivityDoctor.Core.AzureAssessment;
using AzureConnectivityDoctor.Core.Endpoints;
using AzureConnectivityDoctor.Core.Identity;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Options;
using AzureConnectivityDoctor.Core.Probes;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AzureConnectivityDoctor.Core.Execution;

/// <summary>
/// Orchestrates the diagnostic pipeline: parse, DNS, TCP, TLS, certificate, HTTP, identity and
/// the service-aware probes, and then correlates the evidence into findings.
/// </summary>
/// <remarks>
/// <para>
/// Stages are strictly ordered and each one is gated on the stage it depends on. A stage that
/// cannot run is still recorded, either as <see cref="DiagnosticOutcome.Skipped"/> when it does
/// not apply to the target or as <see cref="DiagnosticOutcome.NotAttempted"/> when a prerequisite
/// failed. A report therefore always contains a full row per stage, which is what allows a reader
/// to distinguish "this was fine" from "this was never measured".
/// </para>
/// <para>
/// Endpoints are probed concurrently with a bounded degree of parallelism. Results are written
/// into a pre-sized array by index so the report preserves the order the operator supplied,
/// independently of the order in which the probes finish.
/// </para>
/// </remarks>
public sealed class DiagnosticRunner : IDiagnosticRunner
{
    private readonly DoctorOptions _options;
    private readonly IEndpointParser _endpointParser;
    private readonly IDnsProbe _dnsProbe;
    private readonly ITcpProbe _tcpProbe;
    private readonly ITlsProbe _tlsProbe;
    private readonly IHttpProbe _httpProbe;
    private readonly ITokenProbe _tokenProbe;
    private readonly ISqlProbe _sqlProbe;
    private readonly IServiceBusProbe _serviceBusProbe;
    private readonly IAzureAssessor _azureAssessor;
    private readonly IRootCauseAnalyzer _analyzer;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<DiagnosticRunner> _logger;

    /// <summary>Creates the runner.</summary>
    /// <param name="options">The run options assembled from the command line.</param>
    /// <param name="endpointParser">Normalises raw endpoint text.</param>
    /// <param name="dnsProbe">Resolves host names.</param>
    /// <param name="tcpProbe">Establishes TCP connections.</param>
    /// <param name="tlsProbe">Performs TLS handshakes and inspects certificates.</param>
    /// <param name="httpProbe">Issues HTTP requests.</param>
    /// <param name="tokenProbe">Acquires Microsoft Entra ID tokens.</param>
    /// <param name="sqlProbe">Opens Azure SQL connections.</param>
    /// <param name="serviceBusProbe">Opens Azure Service Bus AMQP links.</param>
    /// <param name="azureAssessor">Reads read-only Azure Resource Manager metadata.</param>
    /// <param name="analyzer">Correlates evidence into findings.</param>
    /// <param name="timeProvider">Supplies the run timestamps; injected so tests are deterministic.</param>
    /// <param name="logger">The logger used for progress output.</param>
    public DiagnosticRunner(
        IOptions<DoctorOptions> options,
        IEndpointParser endpointParser,
        IDnsProbe dnsProbe,
        ITcpProbe tcpProbe,
        ITlsProbe tlsProbe,
        IHttpProbe httpProbe,
        ITokenProbe tokenProbe,
        ISqlProbe sqlProbe,
        IServiceBusProbe serviceBusProbe,
        IAzureAssessor azureAssessor,
        IRootCauseAnalyzer analyzer,
        TimeProvider timeProvider,
        ILogger<DiagnosticRunner> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _options = options.Value;
        _endpointParser = endpointParser;
        _dnsProbe = dnsProbe;
        _tcpProbe = tcpProbe;
        _tlsProbe = tlsProbe;
        _httpProbe = httpProbe;
        _tokenProbe = tokenProbe;
        _sqlProbe = sqlProbe;
        _serviceBusProbe = serviceBusProbe;
        _azureAssessor = azureAssessor;
        _analyzer = analyzer;
        _timeProvider = timeProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<RunReport> RunAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset started = _timeProvider.GetUtcNow();

        using CancellationTokenSource runSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        if (_options.OverallTimeout > TimeSpan.Zero)
        {
            runSource.CancelAfter(_options.OverallTimeout);
        }

        CancellationToken runToken = runSource.Token;
        bool cancelled = false;

        IReadOnlyList<string> endpoints = await ReadEndpointsAsync(runToken).ConfigureAwait(false);
        _logger.LogInformation("Diagnosing {EndpointCount} endpoint(s).", endpoints.Count);

        List<StageResult> azureAssessment = [];

        try
        {
            azureAssessment.AddRange(await RunAzureAssessmentAsync(runToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }

        TargetReport?[] slots = new TargetReport?[endpoints.Count];

        if (!cancelled && endpoints.Count > 0)
        {
            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Math.Max(1, _options.MaxConcurrency),
                CancellationToken = runToken
            };

            try
            {
                await Parallel.ForEachAsync(
                    Enumerable.Range(0, endpoints.Count),
                    parallelOptions,
                    async (index, token) =>
                    {
                        slots[index] = await DiagnoseAsync(endpoints[index], azureAssessment, token)
                            .ConfigureAwait(false);
                    }).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                cancelled = true;
            }
        }

        List<TargetReport> targets = new(endpoints.Count);

        for (int index = 0; index < endpoints.Count; index++)
        {
            targets.Add(slots[index] ?? CancelledReport(endpoints[index]));
        }

        return new RunReport
        {
            ToolVersion = ResolveToolVersion(),
            StartedUtc = started,
            CompletedUtc = _timeProvider.GetUtcNow(),
            Runtime = RuntimeContextProvider.Capture(),
            Cancelled = cancelled,
            Targets = targets,
            AzureAssessment = azureAssessment
        };
    }

    /// <summary>Merges the inline endpoint list with the optional endpoint file.</summary>
    private async Task<IReadOnlyList<string>> ReadEndpointsAsync(CancellationToken cancellationToken)
    {
        List<string> endpoints = [.. _options.Endpoints.Where(value => !string.IsNullOrWhiteSpace(value))];

        if (string.IsNullOrWhiteSpace(_options.EndpointsFile))
        {
            return endpoints;
        }

        string[] lines = await File
            .ReadAllLinesAsync(_options.EndpointsFile, cancellationToken)
            .ConfigureAwait(false);

        foreach (string line in lines)
        {
            string trimmed = line.Trim();

            // Blank lines and '#' comments keep endpoint files readable and reviewable.
            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
            {
                continue;
            }

            endpoints.Add(trimmed);
        }

        return endpoints;
    }

    /// <summary>Reads the optional, read-only Azure Resource Manager evidence.</summary>
    private async Task<IReadOnlyList<StageResult>> RunAzureAssessmentAsync(CancellationToken cancellationToken)
    {
        if (!_options.EnableAzureAssessment)
        {
            return
            [
                StageResult.Skipped(
                    DiagnosticStage.AzureResourceAssessment,
                    "The Azure assessment is disabled. Pass --azure-assessment to enable it.")
            ];
        }

        if (_options.ResourceIds.Count == 0)
        {
            return
            [
                StageResult.Skipped(
                    DiagnosticStage.AzureResourceAssessment,
                    "The Azure assessment is enabled but no --resource-id was supplied.")
            ];
        }

        List<StageResult> results = new(_options.ResourceIds.Count);

        // Resource reads are sequential: they share one credential and one ARM client, and the
        // request volume is tiny compared with the network probes.
        foreach (string resourceId in _options.ResourceIds)
        {
            results.Add(await _azureAssessor.AssessAsync(resourceId, cancellationToken).ConfigureAwait(false));
        }

        return results;
    }

    /// <summary>Runs the full stage pipeline for one endpoint.</summary>
    private async Task<TargetReport> DiagnoseAsync(
        string rawValue,
        IReadOnlyList<StageResult> azureAssessment,
        CancellationToken cancellationToken)
    {
        List<StageResult> stages = [];
        TargetParseResult parsed = _endpointParser.Parse(rawValue);

        if (!parsed.Succeeded || parsed.Target is null)
        {
            stages.Add(new StageResult
            {
                Stage = DiagnosticStage.EndpointParsing,
                Outcome = DiagnosticOutcome.Failed,
                Summary = parsed.Error ?? "The endpoint could not be parsed.",
                Evidence = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["rawValue"] = SecretRedactor.Redact(rawValue) ?? string.Empty
                }
            });

            return new TargetReport
            {
                RawValue = rawValue,
                Target = null,
                Stages = stages,
                Findings = _analyzer.Analyze(null, stages, azureAssessment)
            };
        }

        ProbeTarget target = parsed.Target;
        stages.Add(DescribeParse(target));

        TimeSpan timeout = _options.Timeout;

        DnsProbeResult dns = await _dnsProbe.ResolveAsync(target, timeout, cancellationToken)
            .ConfigureAwait(false);
        stages.Add(dns.Result);

        IPAddress? connectedAddress = null;

        if (dns.Addresses.Count == 0)
        {
            stages.Add(StageResult.NotAttempted(
                DiagnosticStage.TcpConnect,
                "The host could not be resolved, so no address was available to connect to."));
        }
        else
        {
            TcpProbeResult tcp = await _tcpProbe
                .ConnectAsync(target, dns.Addresses, timeout, cancellationToken)
                .ConfigureAwait(false);
            stages.Add(tcp.Result);
            connectedAddress = tcp.ConnectedAddress;
        }

        stages.AddRange(await RunTlsStagesAsync(target, connectedAddress, timeout, cancellationToken)
            .ConfigureAwait(false));

        stages.Add(await RunHttpStageAsync(target, connectedAddress, timeout, cancellationToken)
            .ConfigureAwait(false));

        TokenProbeResult identity = await RunIdentityStageAsync(target, cancellationToken)
            .ConfigureAwait(false);
        stages.Add(identity.Stage);

        stages.Add(await RunSqlStageAsync(target, connectedAddress, identity.Token, timeout, cancellationToken)
            .ConfigureAwait(false));

        stages.Add(await RunServiceBusStageAsync(target, connectedAddress, timeout, cancellationToken)
            .ConfigureAwait(false));

        return new TargetReport
        {
            RawValue = rawValue,
            Target = target,
            Stages = stages,
            Findings = _analyzer.Analyze(target, stages, azureAssessment)
        };
    }

    private async Task<IReadOnlyList<StageResult>> RunTlsStagesAsync(
        ProbeTarget target,
        IPAddress? connectedAddress,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (!target.TlsOnConnect)
        {
            string reason = target.ServiceKind == ServiceKind.AzureSql
                ? "Azure SQL negotiates TLS inside the TDS protocol rather than on connect, so a " +
                  "direct TLS handshake would be misleading. Encryption is verified by the Azure SQL stage."
                : "The endpoint does not negotiate TLS immediately after the TCP connection.";

            return
            [
                StageResult.Skipped(DiagnosticStage.TlsHandshake, reason),
                StageResult.Skipped(DiagnosticStage.CertificateValidation, reason)
            ];
        }

        if (connectedAddress is null)
        {
            const string Reason = "The TCP connection did not succeed, so no TLS handshake was possible.";

            return
            [
                StageResult.NotAttempted(DiagnosticStage.TlsHandshake, Reason),
                StageResult.NotAttempted(DiagnosticStage.CertificateValidation, Reason)
            ];
        }

        TlsProbeResult tls = await _tlsProbe
            .HandshakeAsync(target, connectedAddress, timeout, cancellationToken)
            .ConfigureAwait(false);

        return [tls.Handshake, tls.Certificate];
    }

    private async Task<StageResult> RunHttpStageAsync(
        ProbeTarget target,
        IPAddress? connectedAddress,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (target.ServiceKind != ServiceKind.Http || target.HttpUri is null)
        {
            return StageResult.Skipped(
                DiagnosticStage.HttpRequest,
                "The endpoint is not an HTTP or HTTPS URL.");
        }

        if (!_options.EnableHttp)
        {
            return StageResult.Skipped(
                DiagnosticStage.HttpRequest,
                "HTTP probing is disabled. Pass --http to send a request to the endpoint.");
        }

        if (connectedAddress is null)
        {
            return StageResult.NotAttempted(
                DiagnosticStage.HttpRequest,
                "The TCP connection did not succeed, so no HTTP request was sent.");
        }

        return await _httpProbe.SendAsync(target, timeout, cancellationToken).ConfigureAwait(false);
    }

    private async Task<TokenProbeResult> RunIdentityStageAsync(
        ProbeTarget target,
        CancellationToken cancellationToken)
    {
        string? scope = target.ServiceKind switch
        {
            ServiceKind.AzureSql => AzureScopes.ForSql(target.Host),
            ServiceKind.AzureServiceBus => AzureScopes.ForServiceBus(target.Host),
            _ => null
        };

        if (scope is null)
        {
            return new TokenProbeResult(
                StageResult.Skipped(
                    DiagnosticStage.IdentityTokenAcquisition,
                    "The endpoint is not an Azure service that this tool authenticates to."),
                Token: null);
        }

        if (!_options.EnableIdentity)
        {
            return new TokenProbeResult(
                StageResult.Skipped(
                    DiagnosticStage.IdentityTokenAcquisition,
                    "Identity probing is disabled. Pass --identity to acquire a token and run the " +
                    "authenticated service probes."),
                Token: null);
        }

        return await _tokenProbe.AcquireAsync(scope, cancellationToken).ConfigureAwait(false);
    }

    private async Task<StageResult> RunSqlStageAsync(
        ProbeTarget target,
        IPAddress? connectedAddress,
        string? accessToken,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (target.ServiceKind != ServiceKind.AzureSql)
        {
            return StageResult.Skipped(
                DiagnosticStage.SqlConnection,
                "The endpoint is not an Azure SQL logical server.");
        }

        if (!_options.EnableIdentity)
        {
            return StageResult.Skipped(
                DiagnosticStage.SqlConnection,
                "Identity probing is disabled, so no authenticated Azure SQL connection was opened. " +
                "Pass --identity to enable it.");
        }

        if (connectedAddress is null)
        {
            return StageResult.NotAttempted(
                DiagnosticStage.SqlConnection,
                "The TCP connection did not succeed, so no Azure SQL connection was opened.");
        }

        return await _sqlProbe
            .ProbeAsync(target, accessToken, timeout, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<StageResult> RunServiceBusStageAsync(
        ProbeTarget target,
        IPAddress? connectedAddress,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (target.ServiceKind != ServiceKind.AzureServiceBus)
        {
            return StageResult.Skipped(
                DiagnosticStage.ServiceBusLink,
                "The endpoint is not an Azure Service Bus namespace.");
        }

        if (!_options.EnableIdentity)
        {
            return StageResult.Skipped(
                DiagnosticStage.ServiceBusLink,
                "Identity probing is disabled, so no authenticated Service Bus link was opened. " +
                "Pass --identity to enable it.");
        }

        if (connectedAddress is null)
        {
            return StageResult.NotAttempted(
                DiagnosticStage.ServiceBusLink,
                "The TCP connection did not succeed, so no Service Bus link was opened.");
        }

        // Port 443 means the operator asked for the AMQP-over-WebSockets transport, which is the
        // documented workaround for environments that block outbound 5671.
        bool useWebSockets = target.Port == 443;

        return await _serviceBusProbe
            .ProbeAsync(target, useWebSockets, timeout, cancellationToken)
            .ConfigureAwait(false);
    }

    private static StageResult DescribeParse(ProbeTarget target)
    {
        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["host"] = target.Host,
            ["port"] = target.Port.ToString(CultureInfo.InvariantCulture),
            ["serviceKind"] = target.ServiceKind.ToString(),
            ["tlsOnConnect"] = target.TlsOnConnect ? "true" : "false",
            ["hostIsIpLiteral"] = target.HostIsIpLiteral ? "true" : "false"
        };

        if (target.HttpUri is not null)
        {
            evidence["requestUri"] = target.HttpUri.ToString();
        }

        if (!string.IsNullOrEmpty(target.DatabaseName))
        {
            evidence["databaseName"] = target.DatabaseName;
        }

        if (!string.IsNullOrEmpty(target.EntityName))
        {
            evidence["entityName"] = target.EntityName;
        }

        return new StageResult
        {
            Stage = DiagnosticStage.EndpointParsing,
            Outcome = DiagnosticOutcome.Succeeded,
            Summary =
                $"The endpoint was read as {target.ServiceKind} at {target.DisplayName}.",
            Evidence = evidence
        };
    }

    private static TargetReport CancelledReport(string rawValue)
    {
        return new TargetReport
        {
            RawValue = rawValue,
            Stages =
            [
                StageResult.NotAttempted(
                    DiagnosticStage.EndpointParsing,
                    "The run ended before this endpoint was diagnosed.")
            ]
        };
    }

    /// <summary>Reads the informational version stamped into the assembly by the build.</summary>
    private static string ResolveToolVersion()
    {
        Assembly assembly = typeof(DiagnosticRunner).Assembly;

        string? informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (!string.IsNullOrEmpty(informational))
        {
            // SourceLink appends '+<commit sha>'; the sha is not useful in a report heading.
            int plusIndex = informational.IndexOf('+', StringComparison.Ordinal);
            return plusIndex < 0 ? informational : informational[..plusIndex];
        }

        return assembly.GetName().Version?.ToString() ?? "unknown";
    }
}
