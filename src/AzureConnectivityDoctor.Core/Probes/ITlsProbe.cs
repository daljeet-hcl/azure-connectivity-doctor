using System.Net;
using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>Performs a TLS handshake and inspects the server certificate.</summary>
public interface ITlsProbe
{
    /// <summary>Runs the handshake and certificate stages together.</summary>
    /// <param name="target">The endpoint being diagnosed.</param>
    /// <param name="address">The address that accepted the TCP connection.</param>
    /// <param name="timeout">The maximum time to spend on the handshake.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The handshake result and the certificate validation result.</returns>
    Task<TlsProbeResult> HandshakeAsync(
        ProbeTarget target,
        IPAddress address,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

/// <summary>The paired outcome of the TLS handshake and certificate validation stages.</summary>
/// <param name="Handshake">The <see cref="DiagnosticStage.TlsHandshake"/> result.</param>
/// <param name="Certificate">The <see cref="DiagnosticStage.CertificateValidation"/> result.</param>
public sealed record TlsProbeResult(StageResult Handshake, StageResult Certificate);
