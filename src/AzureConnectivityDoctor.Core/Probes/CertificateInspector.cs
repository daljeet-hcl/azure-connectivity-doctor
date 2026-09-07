using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>
/// Extracts the certificate facts that matter for connectivity diagnosis.
/// </summary>
/// <remarks>
/// Only three certificate problems account for almost all real outbound TLS failures:
/// an expired certificate, a host name that is not covered by the subject alternative names,
/// and a chain that does not terminate in a root the client trusts. The third is the signature
/// of a TLS-inspecting middlebox. This class gathers exactly the evidence needed to tell them
/// apart and nothing else.
/// </remarks>
public static class CertificateInspector
{
    private const string SubjectAlternativeNameOid = "2.5.29.17";

    /// <summary>
    /// Reads the subject alternative DNS names from a certificate.
    /// </summary>
    /// <param name="certificate">The certificate to inspect.</param>
    /// <returns>The DNS names, or an empty list when the extension is absent or malformed.</returns>
    public static IReadOnlyList<string> GetDnsNames(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        foreach (X509Extension extension in certificate.Extensions)
        {
            if (!string.Equals(extension.Oid?.Value, SubjectAlternativeNameOid, StringComparison.Ordinal))
            {
                continue;
            }

            try
            {
                var subjectAlternativeName =
                    new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
                return [.. subjectAlternativeName.EnumerateDnsNames()];
            }
            catch (AsnContentException)
            {
                // A malformed extension is itself worth knowing about, but it must not crash the run.
                return [];
            }
            catch (CryptographicException)
            {
                return [];
            }
        }

        return [];
    }

    /// <summary>
    /// Determines whether a host name is covered by a certificate's subject alternative names.
    /// </summary>
    /// <param name="hostName">The host name that was connected to.</param>
    /// <param name="dnsNames">The certificate's DNS names, including wildcard entries.</param>
    /// <returns><see langword="true"/> when at least one name matches.</returns>
    /// <remarks>
    /// Wildcard matching follows RFC 6125: a leading <c>*.</c> matches exactly one label, so
    /// <c>*.example.com</c> matches <c>api.example.com</c> but not <c>a.b.example.com</c> and not
    /// the bare <c>example.com</c>.
    /// </remarks>
    public static bool MatchesHostName(string hostName, IReadOnlyList<string> dnsNames)
    {
        ArgumentNullException.ThrowIfNull(dnsNames);

        if (string.IsNullOrEmpty(hostName))
        {
            return false;
        }

        string candidate = hostName.TrimEnd('.');

        foreach (string dnsName in dnsNames)
        {
            string pattern = dnsName.TrimEnd('.');

            if (string.Equals(pattern, candidate, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            if (!pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                continue;
            }

            string patternRemainder = pattern[2..];
            int firstDot = candidate.IndexOf('.', StringComparison.Ordinal);
            if (firstDot <= 0)
            {
                continue;
            }

            string candidateRemainder = candidate[(firstDot + 1)..];
            if (string.Equals(patternRemainder, candidateRemainder, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Collects the descriptive facts about a certificate for the report.
    /// </summary>
    /// <param name="certificate">The certificate presented by the server.</param>
    /// <param name="hostName">The host name that was requested.</param>
    /// <param name="now">The current time, injected so the check is testable.</param>
    /// <returns>A flat evidence dictionary.</returns>
    public static Dictionary<string, string> Describe(
        X509Certificate2 certificate,
        string hostName,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        IReadOnlyList<string> dnsNames = GetDnsNames(certificate);
        DateTimeOffset notBefore = new(certificate.NotBefore.ToUniversalTime(), TimeSpan.Zero);
        DateTimeOffset notAfter = new(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero);

        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["subject"] = certificate.Subject,
            ["issuer"] = certificate.Issuer,
            ["thumbprintSha1"] = certificate.Thumbprint,
            ["serialNumber"] = certificate.SerialNumber,
            ["signatureAlgorithm"] = certificate.SignatureAlgorithm.FriendlyName ?? certificate.SignatureAlgorithm.Value ?? "unknown",
            ["notBeforeUtc"] = notBefore.ToString("O", CultureInfo.InvariantCulture),
            ["notAfterUtc"] = notAfter.ToString("O", CultureInfo.InvariantCulture),
            ["daysUntilExpiry"] = (notAfter - now).TotalDays.ToString("F1", CultureInfo.InvariantCulture),
            ["isCurrentlyValid"] = (now >= notBefore && now <= notAfter).ToString(CultureInfo.InvariantCulture),
            ["subjectAlternativeNames"] = dnsNames.Count == 0 ? "(none)" : string.Join(", ", dnsNames),
            ["hostNameMatchesCertificate"] = MatchesHostName(hostName, dnsNames).ToString(CultureInfo.InvariantCulture),
            ["isSelfSigned"] = string.Equals(certificate.Subject, certificate.Issuer, StringComparison.Ordinal)
                .ToString(CultureInfo.InvariantCulture)
        };

        return evidence;
    }
}
