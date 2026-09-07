using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Extensions.Logging;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>
/// Completes a TLS handshake and reports what the server presented.
/// </summary>
/// <remarks>
/// <para>
/// <b>Design note on certificate validation.</b> The remote certificate validation callback
/// records the validation errors and then returns <see langword="true"/>, allowing the
/// handshake to complete even when the certificate would normally be rejected. This is done so
/// the tool can report <i>why</i> validation failed rather than only that it failed — an
/// aborted handshake yields an opaque "authentication failed" message that tells an operator
/// nothing.
/// </para>
/// <para>
/// This is safe here, and only here, because the connection is used for absolutely nothing:
/// no bytes are ever written to the stream and no bytes are ever read from it. The socket is
/// closed immediately after the handshake completes. The report always states the true
/// validation outcome, so a certificate that would be rejected by a real client is reported
/// as a failure.
/// </para>
/// </remarks>
public sealed class TlsProbe : ITlsProbe
{
    private readonly ILogger<TlsProbe> _logger;
    private readonly TimeProvider _timeProvider;

    /// <summary>Creates the probe.</summary>
    /// <param name="logger">The logger used for progress output.</param>
    /// <param name="timeProvider">Supplies the current time, injected for testability.</param>
    public TlsProbe(ILogger<TlsProbe> logger, TimeProvider timeProvider)
    {
        _logger = logger;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc />
    public async Task<TlsProbeResult> HandshakeAsync(
        ProbeTarget target,
        IPAddress address,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(address);

        _logger.LogInformation("Starting TLS handshake with {Host} via {Address}", target.Host, address);

        SslPolicyErrors policyErrors = SslPolicyErrors.None;
        var chainStatuses = new List<string>();
        X509Certificate2? serverCertificate = null;
        long start = Stopwatch.GetTimestamp();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            using var client = new TcpClient(address.AddressFamily);
            client.NoDelay = true;
            await client.ConnectAsync(address, target.Port, timeoutSource.Token);

            await using NetworkStream networkStream = client.GetStream();
            await using var sslStream = new SslStream(networkStream, leaveInnerStreamOpen: false);

            var authenticationOptions = new SslClientAuthenticationOptions
            {
                TargetHost = target.Host,
                EnabledSslProtocols = SslProtocols.None, // Let the OS pick the best mutually supported version.
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                {
                    policyErrors = errors;

                    if (certificate is not null)
                    {
                        serverCertificate = certificate as X509Certificate2
                            ?? X509CertificateLoader.LoadCertificate(certificate.Export(X509ContentType.Cert));
                    }

                    if (chain is not null)
                    {
                        foreach (X509ChainStatus status in chain.ChainStatus)
                        {
                            chainStatuses.Add(status.Status.ToString());
                        }
                    }

                    // Always accept, then report the truth. See the class remarks.
                    return true;
                }
            };

            await sslStream.AuthenticateAsClientAsync(authenticationOptions, timeoutSource.Token);
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            var handshakeEvidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["targetHost"] = target.Host,
                ["negotiatedProtocol"] = sslStream.SslProtocol.ToString(),
                ["negotiatedCipherSuite"] = DescribeCipherSuite(sslStream),
                ["isEncrypted"] = sslStream.IsEncrypted.ToString(CultureInfo.InvariantCulture),
                ["isSigned"] = sslStream.IsSigned.ToString(CultureInfo.InvariantCulture),
                ["isMutuallyAuthenticated"] = sslStream.IsMutuallyAuthenticated.ToString(CultureInfo.InvariantCulture),
                ["handshakeMilliseconds"] = elapsed.ToString("F1", CultureInfo.InvariantCulture)
            };

            var handshakeResult = new StageResult
            {
                Stage = DiagnosticStage.TlsHandshake,
                Outcome = DiagnosticOutcome.Succeeded,
                Summary =
                    $"TLS handshake completed using {sslStream.SslProtocol} in {elapsed:F0} ms.",
                DurationMilliseconds = elapsed,
                Evidence = handshakeEvidence
            };

            StageResult certificateResult = EvaluateCertificate(
                target,
                serverCertificate,
                policyErrors,
                chainStatuses);

            return new TlsProbeResult(handshakeResult, certificateResult);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            return new TlsProbeResult(
                new StageResult
                {
                    Stage = DiagnosticStage.TlsHandshake,
                    Outcome = DiagnosticOutcome.Failed,
                    Summary =
                        $"The TLS handshake with {target.Host}:{target.Port} did not complete within " +
                        $"{timeout.TotalSeconds:F0} s. A handshake that hangs after a successful TCP connect " +
                        "usually indicates a middlebox holding the connection open.",
                    DurationMilliseconds = elapsed,
                    ErrorType = nameof(TimeoutException)
                },
                StageResult.NotAttempted(
                    DiagnosticStage.CertificateValidation,
                    "No certificate was presented, because the handshake did not complete."));
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["targetHost"] = target.Host,
                ["sslPolicyErrors"] = policyErrors.ToString(),
                ["chainStatus"] = chainStatuses.Count == 0 ? "(none)" : string.Join(", ", chainStatuses)
            };

            if (exception is AuthenticationException && exception.InnerException is not null)
            {
                evidence["innerErrorType"] = exception.InnerException.GetType().Name;
                evidence["innerErrorMessage"] =
                    SecretRedactor.Redact(exception.InnerException.Message) ?? string.Empty;
            }

            var handshakeFailure = new StageResult
            {
                Stage = DiagnosticStage.TlsHandshake,
                Outcome = DiagnosticOutcome.Failed,
                Summary = $"The TLS handshake with {target.Host}:{target.Port} failed.",
                DurationMilliseconds = elapsed,
                ErrorType = exception.GetType().Name,
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            };

            StageResult certificateResult = serverCertificate is null
                ? StageResult.NotAttempted(
                    DiagnosticStage.CertificateValidation,
                    "No certificate was presented before the handshake failed.")
                : EvaluateCertificate(target, serverCertificate, policyErrors, chainStatuses);

            return new TlsProbeResult(handshakeFailure, certificateResult);
        }
        finally
        {
            serverCertificate?.Dispose();
        }
    }

    private StageResult EvaluateCertificate(
        ProbeTarget target,
        X509Certificate2? certificate,
        SslPolicyErrors policyErrors,
        IReadOnlyList<string> chainStatuses)
    {
        if (certificate is null)
        {
            return new StageResult
            {
                Stage = DiagnosticStage.CertificateValidation,
                Outcome = DiagnosticOutcome.Inconclusive,
                Summary = "The handshake completed but no server certificate was captured."
            };
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        Dictionary<string, string> evidence = CertificateInspector.Describe(certificate, target.Host, now);
        evidence["sslPolicyErrors"] = policyErrors.ToString();
        evidence["chainStatus"] = chainStatuses.Count == 0 ? "(none)" : string.Join(", ", chainStatuses);

        bool nameMatches = string.Equals(
            evidence["hostNameMatchesCertificate"],
            bool.TrueString,
            StringComparison.OrdinalIgnoreCase);
        bool currentlyValid = string.Equals(
            evidence["isCurrentlyValid"],
            bool.TrueString,
            StringComparison.OrdinalIgnoreCase);

        if (policyErrors == SslPolicyErrors.None)
        {
            return new StageResult
            {
                Stage = DiagnosticStage.CertificateValidation,
                Outcome = DiagnosticOutcome.Succeeded,
                Summary =
                    $"The server certificate is trusted, currently valid and covers '{target.Host}'. " +
                    $"Issued by {certificate.Issuer}.",
                Evidence = evidence
            };
        }

        var problems = new List<string>();
        if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable))
        {
            problems.Add("the server did not present a certificate");
        }

        if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) || !nameMatches)
        {
            problems.Add($"the certificate does not cover the host name '{target.Host}'");
        }

        if (policyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
        {
            problems.Add(
                chainStatuses.Count == 0
                    ? "the certificate chain could not be validated"
                    : $"the certificate chain reported {string.Join(", ", chainStatuses)}");
        }

        if (!currentlyValid)
        {
            problems.Add("the certificate is outside its validity period");
        }

        return new StageResult
        {
            Stage = DiagnosticStage.CertificateValidation,
            Outcome = DiagnosticOutcome.Failed,
            Summary = $"Certificate validation failed: {string.Join("; ", problems)}.",
            Evidence = evidence
        };
    }

    /// <summary>
    /// Reads the negotiated cipher suite, tolerating platforms that do not expose it.
    /// </summary>
    private static string DescribeCipherSuite(SslStream sslStream)
    {
        try
        {
            return sslStream.NegotiatedCipherSuite.ToString();
        }
        catch (PlatformNotSupportedException)
        {
            return "(not reported by this platform)";
        }
    }
}
