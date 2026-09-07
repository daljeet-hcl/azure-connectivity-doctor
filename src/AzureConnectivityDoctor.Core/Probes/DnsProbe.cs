using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Extensions.Logging;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>
/// Resolves host names using the managed <see cref="Dns"/> API.
/// </summary>
/// <remarks>
/// <para>
/// The tool deliberately uses the platform resolver rather than sending its own DNS packets.
/// The question an operator needs answered is "what does *this process* see?", and only the
/// platform resolver reflects the container's <c>/etc/resolv.conf</c>, the App Service DNS
/// override, the Kubernetes cluster DNS and any private DNS zone links that apply.
/// </para>
/// <para>
/// Known limitation: the managed API returns addresses only, never the CNAME chain. A private
/// endpoint is therefore inferred from the address scope rather than from the presence of a
/// <c>privatelink</c> alias. This is recorded as <see cref="EvidenceConfidence.Inferred"/> in
/// any finding that depends on it.
/// </para>
/// </remarks>
public sealed class DnsProbe : IDnsProbe
{
    private readonly ILogger<DnsProbe> _logger;

    /// <summary>Creates the probe.</summary>
    /// <param name="logger">The logger used for progress output.</param>
    public DnsProbe(ILogger<DnsProbe> logger)
    {
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<DnsProbeResult> ResolveAsync(
        ProbeTarget target,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (target.HostIsIpLiteral)
        {
            IPAddress literal = IPAddress.Parse(target.Host);
            var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["host"] = target.Host,
                ["addressCount"] = "1",
                ["addresses"] = literal.ToString(),
                ["addressScopes"] = IpAddressClassifier.DescribeScope(literal)
            };

            var skipped = new StageResult
            {
                Stage = DiagnosticStage.DnsResolution,
                Outcome = DiagnosticOutcome.Skipped,
                Summary = "The host is already an IP address literal, so no name resolution was needed.",
                Evidence = evidence
            };

            return new DnsProbeResult(skipped, [literal]);
        }

        _logger.LogInformation("Resolving {Host}", target.Host);

        long start = Stopwatch.GetTimestamp();
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            IPAddress[] addresses = await Dns.GetHostAddressesAsync(target.Host, timeoutSource.Token);
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            if (addresses.Length == 0)
            {
                return new DnsProbeResult(
                    new StageResult
                    {
                        Stage = DiagnosticStage.DnsResolution,
                        Outcome = DiagnosticOutcome.Failed,
                        Summary = $"'{target.Host}' resolved to zero addresses.",
                        DurationMilliseconds = elapsed,
                        Evidence = new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            ["host"] = target.Host,
                            ["addressCount"] = "0"
                        }
                    },
                    []);
            }

            int ipv4Count = addresses.Count(a => a.AddressFamily == AddressFamily.InterNetwork);
            int ipv6Count = addresses.Count(a => a.AddressFamily == AddressFamily.InterNetworkV6);
            int privateCount = addresses.Count(IpAddressClassifier.IsPrivate);

            var resolvedEvidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["host"] = target.Host,
                ["addressCount"] = addresses.Length.ToString(CultureInfo.InvariantCulture),
                ["addresses"] = string.Join(", ", addresses.Select(a => a.ToString())),
                ["addressScopes"] = string.Join(", ", addresses.Select(IpAddressClassifier.DescribeScope)),
                ["ipv4Count"] = ipv4Count.ToString(CultureInfo.InvariantCulture),
                ["ipv6Count"] = ipv6Count.ToString(CultureInfo.InvariantCulture),
                ["privateAddressCount"] = privateCount.ToString(CultureInfo.InvariantCulture),
                ["allAddressesPrivate"] = (privateCount == addresses.Length).ToString(CultureInfo.InvariantCulture),
                ["hostLooksLikeAzurePaas"] = LooksLikeAzurePaasHost(target.Host).ToString(CultureInfo.InvariantCulture)
            };

            return new DnsProbeResult(
                new StageResult
                {
                    Stage = DiagnosticStage.DnsResolution,
                    Outcome = DiagnosticOutcome.Succeeded,
                    Summary = $"'{target.Host}' resolved to {addresses.Length} address(es) in {elapsed:F0} ms.",
                    DurationMilliseconds = elapsed,
                    Evidence = resolvedEvidence
                },
                addresses);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            return new DnsProbeResult(
                new StageResult
                {
                    Stage = DiagnosticStage.DnsResolution,
                    Outcome = DiagnosticOutcome.Failed,
                    Summary =
                        $"Resolving '{target.Host}' did not complete within {timeout.TotalSeconds:F0} s. " +
                        "A DNS timeout usually means the configured resolver is unreachable, not that the name is wrong.",
                    DurationMilliseconds = elapsed,
                    ErrorType = nameof(TimeoutException),
                    Evidence = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["host"] = target.Host,
                        ["timeoutSeconds"] = timeout.TotalSeconds.ToString("F0", CultureInfo.InvariantCulture)
                    }
                },
                []);
        }
        catch (SocketException exception)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            return new DnsProbeResult(
                new StageResult
                {
                    Stage = DiagnosticStage.DnsResolution,
                    Outcome = DiagnosticOutcome.Failed,
                    Summary = $"'{target.Host}' could not be resolved: {exception.SocketErrorCode}.",
                    DurationMilliseconds = elapsed,
                    ErrorType = nameof(SocketException),
                    ErrorMessage = SecretRedactor.Redact(exception.Message),
                    Evidence = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["host"] = target.Host,
                        ["socketError"] = exception.SocketErrorCode.ToString(),
                        ["nativeErrorCode"] = exception.ErrorCode.ToString(CultureInfo.InvariantCulture)
                    }
                },
                []);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            return new DnsProbeResult(
                new StageResult
                {
                    Stage = DiagnosticStage.DnsResolution,
                    Outcome = DiagnosticOutcome.Failed,
                    Summary = $"'{target.Host}' could not be resolved.",
                    DurationMilliseconds = elapsed,
                    ErrorType = exception.GetType().Name,
                    ErrorMessage = SecretRedactor.Redact(exception.Message),
                    Evidence = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["host"] = target.Host
                    }
                },
                []);
        }
    }

    /// <summary>
    /// Recognises host names belonging to Azure PaaS services that support Private Endpoint.
    /// </summary>
    internal static bool LooksLikeAzurePaasHost(string host)
    {
        string[] suffixes =
        [
            ".database.windows.net",
            ".servicebus.windows.net",
            ".blob.core.windows.net",
            ".file.core.windows.net",
            ".queue.core.windows.net",
            ".table.core.windows.net",
            ".vault.azure.net",
            ".documents.azure.com",
            ".azurewebsites.net",
            ".redis.cache.windows.net",
            ".search.windows.net",
            ".azurecr.io"
        ];

        foreach (string suffix in suffixes)
        {
            if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
