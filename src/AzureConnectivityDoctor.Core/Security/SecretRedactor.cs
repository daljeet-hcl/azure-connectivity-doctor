using System.Text.RegularExpressions;

namespace AzureConnectivityDoctor.Core.Security;

/// <summary>
/// Removes credential material from any text before it is written to a report, a log or the console.
/// </summary>
/// <remarks>
/// <para>
/// Diagnostic tools are routinely run with a connection string pasted straight onto the command
/// line, and the resulting report is routinely pasted into a support ticket. Redaction is applied
/// centrally, at the last possible moment, so that no probe author has to remember to do it.
/// </para>
/// <para>
/// This is defence in depth, not a licence to handle secrets casually. The tool never asks for a
/// password and never writes one deliberately; these patterns catch the cases where a secret
/// arrives inside an endpoint string or is echoed back inside a third-party exception message.
/// </para>
/// </remarks>
public static partial class SecretRedactor
{
    /// <summary>The text substituted in place of any detected secret.</summary>
    public const string Placeholder = "***REDACTED***";

    private const int RegexTimeoutMilliseconds = 1000;

    /// <summary>
    /// Returns <paramref name="value"/> with any recognised credential material replaced by
    /// <see cref="Placeholder"/>.
    /// </summary>
    /// <param name="value">The text to redact. May be <see langword="null"/>.</param>
    /// <returns>The redacted text, or <see langword="null"/> when the input was null.</returns>
    public static string? Redact(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        string result = value;
        result = KeyValueSecretRegex().Replace(result, match => match.Groups["key"].Value + "=" + Placeholder);
        result = BearerTokenRegex().Replace(result, "Bearer " + Placeholder);
        result = SasSignatureRegex().Replace(result, match => match.Groups["key"].Value + "=" + Placeholder);
        result = JwtRegex().Replace(result, Placeholder);
        return result;
    }

    /// <summary>
    /// Redacts every value in an evidence dictionary. Keys are never secret and are preserved.
    /// </summary>
    /// <param name="evidence">The evidence to redact.</param>
    /// <returns>A new dictionary with redacted values.</returns>
    public static IReadOnlyDictionary<string, string> RedactEvidence(
        IReadOnlyDictionary<string, string> evidence)
    {
        var redacted = new Dictionary<string, string>(evidence.Count, StringComparer.Ordinal);
        foreach (KeyValuePair<string, string> entry in evidence)
        {
            redacted[entry.Key] = Redact(entry.Value) ?? string.Empty;
        }

        return redacted;
    }

    // Matches connection-string style assignments whose key names a credential.
    [GeneratedRegex(
        "(?<key>password|pwd|sharedaccesskey|accountkey|secret|apikey|api_key|client_secret|access_token|authorization)\\s*=\\s*[^;,\\s\"']+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        RegexTimeoutMilliseconds)]
    private static partial Regex KeyValueSecretRegex();

    // Matches an HTTP Authorization bearer value.
    [GeneratedRegex(
        "Bearer\\s+[A-Za-z0-9\\-._~+/]+=*",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        RegexTimeoutMilliseconds)]
    private static partial Regex BearerTokenRegex();

    // Matches the signature component of a shared access signature in a query string.
    [GeneratedRegex(
        "(?<key>[?&](?:sig|signature|sas))=[^&\\s]+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        RegexTimeoutMilliseconds)]
    private static partial Regex SasSignatureRegex();

    // Matches a bare three-segment JSON Web Token.
    [GeneratedRegex(
        "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
        RegexOptions.CultureInvariant,
        RegexTimeoutMilliseconds)]
    private static partial Regex JwtRegex();
}
