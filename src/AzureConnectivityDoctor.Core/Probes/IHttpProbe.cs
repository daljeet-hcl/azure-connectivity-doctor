using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>Issues an HTTP request against a target and records the response.</summary>
public interface IHttpProbe
{
    /// <summary>Sends a request to <see cref="ProbeTarget.HttpUri"/>.</summary>
    /// <param name="target">The endpoint being diagnosed.</param>
    /// <param name="timeout">The maximum time to wait for a response.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The HTTP stage result.</returns>
    Task<StageResult> SendAsync(ProbeTarget target, TimeSpan timeout, CancellationToken cancellationToken);
}
