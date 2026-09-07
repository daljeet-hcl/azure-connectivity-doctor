using System.Net;
using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>Establishes a TCP connection to a target.</summary>
public interface ITcpProbe
{
    /// <summary>Attempts a TCP connection to each candidate address in turn.</summary>
    /// <param name="target">The endpoint being diagnosed.</param>
    /// <param name="addresses">The candidate addresses, normally from the DNS stage.</param>
    /// <param name="timeout">The maximum time to spend on each connection attempt.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The stage result and the address that accepted the connection, if any.</returns>
    Task<TcpProbeResult> ConnectAsync(
        ProbeTarget target,
        IReadOnlyList<IPAddress> addresses,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

/// <summary>The outcome of a TCP connection attempt.</summary>
/// <param name="Result">The stage result to record in the report.</param>
/// <param name="ConnectedAddress">The address that accepted the connection, or null.</param>
public sealed record TcpProbeResult(StageResult Result, IPAddress? ConnectedAddress);
