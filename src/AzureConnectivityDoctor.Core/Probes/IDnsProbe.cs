using System.Net;
using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>Resolves the host name of a target to IP addresses.</summary>
public interface IDnsProbe
{
    /// <summary>Resolves <paramref name="target"/> using the platform resolver.</summary>
    /// <param name="target">The endpoint whose host should be resolved.</param>
    /// <param name="timeout">The maximum time to spend resolving.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The stage result and the addresses that were returned.</returns>
    Task<DnsProbeResult> ResolveAsync(
        ProbeTarget target,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

/// <summary>The outcome of a DNS resolution attempt.</summary>
/// <param name="Result">The stage result to record in the report.</param>
/// <param name="Addresses">The addresses that were resolved, in the order returned.</param>
public sealed record DnsProbeResult(StageResult Result, IReadOnlyList<IPAddress> Addresses);
