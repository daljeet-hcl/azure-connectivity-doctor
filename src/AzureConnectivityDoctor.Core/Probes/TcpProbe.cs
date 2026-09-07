using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Extensions.Logging;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>
/// Opens and immediately closes a TCP connection, recording exactly how it failed.
/// </summary>
/// <remarks>
/// <para>
/// The distinction between <see cref="SocketError.TimedOut"/> and
/// <see cref="SocketError.ConnectionRefused"/> carries most of the diagnostic value here, and
/// it is why this tool does not use ICMP ping:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <b>Timed out</b> — the SYN packet was silently dropped. A packet filter (network security
///     group, firewall, service-level firewall or missing route) is discarding traffic.
///   </description></item>
///   <item><description>
///     <b>Connection refused</b> — the SYN reached a host that answered with RST. The network
///     path works; nothing is listening on that port.
///   </description></item>
/// </list>
/// <para>
/// ICMP is blocked by default across Azure's platform load balancers, so a ping-based tool
/// reports failure for endpoints that are perfectly healthy.
/// </para>
/// </remarks>
public sealed class TcpProbe : ITcpProbe
{
    private readonly ILogger<TcpProbe> _logger;

    /// <summary>Creates the probe.</summary>
    /// <param name="logger">The logger used for progress output.</param>
    public TcpProbe(ILogger<TcpProbe> logger)
    {
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<TcpProbeResult> ConnectAsync(
        ProbeTarget target,
        IReadOnlyList<IPAddress> addresses,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(addresses);

        if (addresses.Count == 0)
        {
            return new TcpProbeResult(
                StageResult.NotAttempted(
                    DiagnosticStage.TcpConnect,
                    "No IP address was available, because name resolution did not succeed."),
                null);
        }

        var attempts = new List<string>(addresses.Count);
        SocketError lastSocketError = SocketError.Success;
        string? lastErrorType = null;
        string? lastErrorMessage = null;
        long start = Stopwatch.GetTimestamp();

        foreach (IPAddress address in addresses)
        {
            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogInformation("Connecting to {Address}:{Port}", address, target.Port);

            long attemptStart = Stopwatch.GetTimestamp();
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);

            using var client = new TcpClient(address.AddressFamily);
            client.NoDelay = true;

            try
            {
                await client.ConnectAsync(address, target.Port, timeoutSource.Token);
                double attemptElapsed = Stopwatch.GetElapsedTime(attemptStart).TotalMilliseconds;
                attempts.Add(FormatAttempt(address, "connected", attemptElapsed));

                var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["connectedAddress"] = address.ToString(),
                    ["addressScope"] = IpAddressClassifier.DescribeScope(address),
                    ["port"] = target.Port.ToString(CultureInfo.InvariantCulture),
                    ["connectMilliseconds"] = attemptElapsed.ToString("F1", CultureInfo.InvariantCulture),
                    ["attempts"] = string.Join(" | ", attempts)
                };

                return new TcpProbeResult(
                    new StageResult
                    {
                        Stage = DiagnosticStage.TcpConnect,
                        Outcome = DiagnosticOutcome.Succeeded,
                        Summary =
                            $"TCP connection to {address}:{target.Port} was accepted in {attemptElapsed:F0} ms.",
                        DurationMilliseconds = Stopwatch.GetElapsedTime(start).TotalMilliseconds,
                        Evidence = evidence
                    },
                    address);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                double attemptElapsed = Stopwatch.GetElapsedTime(attemptStart).TotalMilliseconds;
                attempts.Add(FormatAttempt(address, "timed out", attemptElapsed));
                lastSocketError = SocketError.TimedOut;
                lastErrorType = nameof(TimeoutException);
                lastErrorMessage =
                    $"No response within {timeout.TotalSeconds:F0} s.";
            }
            catch (SocketException exception)
            {
                double attemptElapsed = Stopwatch.GetElapsedTime(attemptStart).TotalMilliseconds;
                attempts.Add(FormatAttempt(address, exception.SocketErrorCode.ToString(), attemptElapsed));
                lastSocketError = exception.SocketErrorCode;
                lastErrorType = nameof(SocketException);
                lastErrorMessage = SecretRedactor.Redact(exception.Message);
            }
        }

        double totalElapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
        var failureEvidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["port"] = target.Port.ToString(CultureInfo.InvariantCulture),
            ["attempts"] = string.Join(" | ", attempts),
            ["attemptCount"] = attempts.Count.ToString(CultureInfo.InvariantCulture),
            ["socketError"] = lastSocketError.ToString(),
            ["timeoutSeconds"] = timeout.TotalSeconds.ToString("F0", CultureInfo.InvariantCulture)
        };

        return new TcpProbeResult(
            new StageResult
            {
                Stage = DiagnosticStage.TcpConnect,
                Outcome = DiagnosticOutcome.Failed,
                Summary =
                    $"No TCP connection to {target.Host}:{target.Port} could be established " +
                    $"after {attempts.Count} attempt(s). Last socket error: {lastSocketError}.",
                DurationMilliseconds = totalElapsed,
                ErrorType = lastErrorType,
                ErrorMessage = lastErrorMessage,
                Evidence = failureEvidence
            },
            null);
    }

    private static string FormatAttempt(IPAddress address, string status, double elapsedMilliseconds)
    {
        return string.Create(
            CultureInfo.InvariantCulture,
            $"{address} -> {status} ({elapsedMilliseconds:F0} ms)");
    }
}
