using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>Opens a read-only Azure SQL connection to prove end-to-end reachability.</summary>
public interface ISqlProbe
{
    /// <summary>Connects to the target and runs a trivial read-only query.</summary>
    /// <param name="target">The Azure SQL endpoint being diagnosed.</param>
    /// <param name="accessToken">
    /// A Microsoft Entra ID access token for the SQL scope, or <see langword="null"/> to attempt
    /// the connection without one.
    /// </param>
    /// <param name="timeout">The maximum time to wait for the connection and the query.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The SQL stage result.</returns>
    Task<StageResult> ProbeAsync(
        ProbeTarget target,
        string? accessToken,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}
