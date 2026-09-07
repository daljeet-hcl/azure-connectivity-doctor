using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Identity;

/// <summary>Acquires a Microsoft Entra ID access token for a scope and reports the outcome.</summary>
public interface ITokenProbe
{
    /// <summary>Requests a token and records what happened.</summary>
    /// <param name="scope">The scope to request, for example <c>https://database.windows.net/.default</c>.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The token acquisition stage result.</returns>
    Task<TokenProbeResult> AcquireAsync(string scope, CancellationToken cancellationToken);
}

/// <summary>The outcome of a token acquisition attempt.</summary>
/// <param name="Stage">The stage result for the report.</param>
/// <param name="Token">
/// The raw token, when acquisition succeeded. It is passed to downstream probes and is never
/// written to a report or a log.
/// </param>
public sealed record TokenProbeResult(StageResult Stage, string? Token)
{
    /// <summary>Whether a usable token was obtained.</summary>
    public bool Succeeded => Token is not null;
}
