using System.Globalization;

namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// A single endpoint to diagnose, after parsing and normalisation.
/// </summary>
/// <remarks>
/// This type is immutable. Everything downstream of the parser reads from it and never
/// mutates it, which makes running many targets concurrently safe by construction.
/// </remarks>
public sealed record ProbeTarget
{
    /// <summary>The exact text supplied by the operator, kept for traceability in reports.</summary>
    public required string RawValue { get; init; }

    /// <summary>The host name or IP address literal to connect to.</summary>
    public required string Host { get; init; }

    /// <summary>The TCP port to connect to.</summary>
    public required int Port { get; init; }

    /// <summary>The service kind that determines which protocol-aware probes apply.</summary>
    public required ServiceKind ServiceKind { get; init; }

    /// <summary>
    /// Whether TLS is negotiated immediately after the TCP connection is established.
    /// </summary>
    /// <remarks>
    /// This is <see langword="false"/> for Azure SQL even though Azure SQL traffic is encrypted.
    /// TDS negotiates TLS *inside* the application protocol during the PRELOGIN exchange, not
    /// at connection time, so driving <see cref="System.Net.Security.SslStream"/> straight at
    /// port 1433 would fail and produce a misleading "TLS is broken" report.
    /// </remarks>
    public required bool TlsOnConnect { get; init; }

    /// <summary>The absolute URI to request when <see cref="ServiceKind"/> is HTTP.</summary>
    public Uri? HttpUri { get; init; }

    /// <summary>The Azure SQL database name, when one was supplied.</summary>
    public string? DatabaseName { get; init; }

    /// <summary>The Service Bus queue or topic name, when one was supplied.</summary>
    public string? EntityName { get; init; }

    /// <summary>Whether <see cref="Host"/> is an IP address literal rather than a name.</summary>
    public required bool HostIsIpLiteral { get; init; }

    /// <summary>A short, stable label used as a report heading.</summary>
    public string DisplayName =>
        Host.Contains(':', StringComparison.Ordinal)
            ? string.Create(CultureInfo.InvariantCulture, $"[{Host}]:{Port}")
            : string.Create(CultureInfo.InvariantCulture, $"{Host}:{Port}");
}
