namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// The ordered stages of a connectivity diagnosis.
/// </summary>
/// <remarks>
/// Stages run in the declared order and each one only runs when the stage it depends on
/// succeeded. That ordering is what makes the resulting report diagnostic rather than merely
/// descriptive: a TCP failure that follows a successful DNS resolution has a completely
/// different root cause from a TCP failure that follows a DNS failure.
/// </remarks>
public enum DiagnosticStage
{
    /// <summary>The raw endpoint string was parsed into a host, port and service kind.</summary>
    EndpointParsing = 0,

    /// <summary>The host name was resolved to one or more IP addresses.</summary>
    DnsResolution = 1,

    /// <summary>A TCP connection was established to the resolved address and port.</summary>
    TcpConnect = 2,

    /// <summary>A TLS handshake was completed over the established TCP connection.</summary>
    TlsHandshake = 3,

    /// <summary>The server certificate chain, validity dates and host name were checked.</summary>
    CertificateValidation = 4,

    /// <summary>An HTTP request was issued and a response status was observed.</summary>
    HttpRequest = 5,

    /// <summary>A Microsoft Entra ID access token was requested for the target scope.</summary>
    IdentityTokenAcquisition = 6,

    /// <summary>A protocol-level handshake with Azure SQL was completed.</summary>
    SqlConnection = 7,

    /// <summary>An AMQP link to an Azure Service Bus entity was established.</summary>
    ServiceBusLink = 8,

    /// <summary>Read-only Azure Resource Manager metadata was collected for a resource.</summary>
    AzureResourceAssessment = 9,

    /// <summary>Collected evidence was correlated into findings.</summary>
    RootCauseAnalysis = 10
}
