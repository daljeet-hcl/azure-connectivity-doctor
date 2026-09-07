using System.Diagnostics;
using System.Globalization;
using Azure.Core;
using Azure.Identity;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Extensions.Logging;

namespace AzureConnectivityDoctor.Core.Identity;

/// <summary>
/// Requests an access token and reports the result without ever disclosing the token.
/// </summary>
/// <remarks>
/// Identity is treated as a distinct diagnostic stage because a very large share of "the
/// service is unreachable" reports are actually token failures. Separating them means the
/// report can say "the network path is fine, the identity is not authorised" instead of
/// blaming the network.
/// </remarks>
public sealed class TokenProbe : ITokenProbe
{
    private readonly ICredentialProvider _credentialProvider;
    private readonly ILogger<TokenProbe> _logger;

    /// <summary>Creates the probe.</summary>
    /// <param name="credentialProvider">Supplies the shared credential.</param>
    /// <param name="logger">The logger used for progress output.</param>
    public TokenProbe(ICredentialProvider credentialProvider, ILogger<TokenProbe> logger)
    {
        _credentialProvider = credentialProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<TokenProbeResult> AcquireAsync(string scope, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);

        _logger.LogInformation("Requesting an access token for scope {Scope}", scope);

        TokenCredential credential = _credentialProvider.GetCredential();
        var context = new TokenRequestContext([scope]);
        long start = Stopwatch.GetTimestamp();

        try
        {
            AccessToken token = await credential.GetTokenAsync(context, cancellationToken);
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            // Only non-secret facts about the token are recorded. The token value itself is
            // returned to the caller in memory and never placed in evidence.
            var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["scope"] = scope,
                ["expiresOnUtc"] = token.ExpiresOn.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
                ["validForMinutes"] = (token.ExpiresOn - DateTimeOffset.UtcNow).TotalMinutes
                    .ToString("F0", CultureInfo.InvariantCulture),
                ["tokenLengthCharacters"] = token.Token.Length.ToString(CultureInfo.InvariantCulture),
                ["acquisitionMilliseconds"] = elapsed.ToString("F1", CultureInfo.InvariantCulture)
            };

            return new TokenProbeResult(
                new StageResult
                {
                    Stage = DiagnosticStage.IdentityTokenAcquisition,
                    Outcome = DiagnosticOutcome.Succeeded,
                    Summary =
                        $"An access token for '{scope}' was acquired in {elapsed:F0} ms and is valid until " +
                        $"{token.ExpiresOn.UtcDateTime:u}.",
                    DurationMilliseconds = elapsed,
                    Evidence = evidence
                },
                token.Token);
        }
        catch (CredentialUnavailableException exception)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            return Failure(
                scope,
                elapsed,
                exception,
                "No credential source was available. On Azure App Service or Azure Container Apps, enable " +
                "a managed identity. On a workstation, sign in with a supported developer credential. In " +
                "CI, configure workload identity federation or the standard AZURE_* environment variables.");
        }
        catch (AuthenticationFailedException exception)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            return Failure(
                scope,
                elapsed,
                exception,
                "A credential source was found but the token request was rejected. Check that the identity " +
                "exists in the expected tenant and is granted access to the target resource.");
        }
    }

    private static TokenProbeResult Failure(
        string scope,
        double elapsed,
        Exception exception,
        string guidance)
    {
        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["scope"] = scope,
            ["guidance"] = guidance
        };

        return new TokenProbeResult(
            new StageResult
            {
                Stage = DiagnosticStage.IdentityTokenAcquisition,
                Outcome = DiagnosticOutcome.Failed,
                Summary = $"An access token for '{scope}' could not be acquired.",
                DurationMilliseconds = elapsed,
                ErrorType = exception.GetType().Name,
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            },
            Token: null);
    }
}
