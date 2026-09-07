namespace AzureConnectivityDoctor.Core.Analysis;

/// <summary>
/// The stable identifiers of every finding the analyzer can emit.
/// </summary>
/// <remarks>
/// These codes are a public contract. Dashboards, alert rules and ticket automation match on
/// them, so an existing code must never change meaning. Add a new code instead, and document
/// it in <c>docs/troubleshooting.md</c>.
/// </remarks>
public static class FindingCodes
{
    /// <summary>The endpoint text could not be parsed.</summary>
    public const string ParseFailed = "ACD-PARSE-FAILED";

    /// <summary>The host name does not exist in the resolver's view.</summary>
    public const string DnsNameNotFound = "ACD-DNS-NAME-NOT-FOUND";

    /// <summary>The resolver did not answer in time.</summary>
    public const string DnsTimeout = "ACD-DNS-TIMEOUT";

    /// <summary>Name resolution failed for another reason.</summary>
    public const string DnsFailed = "ACD-DNS-FAILED";

    /// <summary>An Azure PaaS host resolved only to private addresses.</summary>
    public const string PrivateEndpointDns = "ACD-PRIVATE-ENDPOINT-DNS";

    /// <summary>An Azure PaaS host resolved to public addresses but the port is blocked.</summary>
    public const string PublicDnsButBlocked = "ACD-PUBLIC-DNS-BUT-BLOCKED";

    /// <summary>TCP packets were silently dropped.</summary>
    public const string TcpBlocked = "ACD-TCP-BLOCKED";

    /// <summary>The host answered with RST; nothing is listening.</summary>
    public const string TcpRefused = "ACD-TCP-REFUSED";

    /// <summary>No route to the destination.</summary>
    public const string TcpUnreachable = "ACD-TCP-UNREACHABLE";

    /// <summary>The TCP connection failed for another reason.</summary>
    public const string TcpFailed = "ACD-TCP-FAILED";

    /// <summary>TCP succeeded but the TLS handshake did not complete.</summary>
    public const string TlsHandshakeFailed = "ACD-TLS-HANDSHAKE-FAILED";

    /// <summary>The certificate does not cover the requested host name.</summary>
    public const string CertificateNameMismatch = "ACD-CERT-NAME-MISMATCH";

    /// <summary>The certificate is outside its validity period.</summary>
    public const string CertificateExpired = "ACD-CERT-EXPIRED";

    /// <summary>The certificate chain does not reach a trusted root.</summary>
    public const string CertificateUntrustedRoot = "ACD-CERT-UNTRUSTED-ROOT";

    /// <summary>The certificate failed validation for another reason.</summary>
    public const string CertificateInvalid = "ACD-CERT-INVALID";

    /// <summary>The certificate is valid but expires soon.</summary>
    public const string CertificateExpiringSoon = "ACD-CERT-EXPIRING-SOON";

    /// <summary>The server returned HTTP 403.</summary>
    public const string Http403 = "ACD-HTTP-403";

    /// <summary>The server returned HTTP 407.</summary>
    public const string HttpProxyAuthenticationRequired = "ACD-HTTP-PROXY-AUTH";

    /// <summary>An HTTP proxy is configured in the environment.</summary>
    public const string ProxyConfigured = "ACD-PROXY-CONFIGURED";

    /// <summary>No credential source was available.</summary>
    public const string IdentityUnavailable = "ACD-IDENTITY-UNAVAILABLE";

    /// <summary>A credential was found but the token request was rejected.</summary>
    public const string IdentityRejected = "ACD-IDENTITY-REJECTED";

    /// <summary>The Azure SQL server firewall rejected the client address.</summary>
    public const string SqlFirewall = "ACD-SQL-FIREWALL";

    /// <summary>An Azure SQL virtual network rule rejected the connection.</summary>
    public const string SqlVirtualNetworkRule = "ACD-SQL-VNET-RULE";

    /// <summary>The Azure SQL login was rejected.</summary>
    public const string SqlLoginDenied = "ACD-SQL-LOGIN-DENIED";

    /// <summary>The Azure SQL database could not be opened.</summary>
    public const string SqlDatabaseUnavailable = "ACD-SQL-DATABASE-UNAVAILABLE";

    /// <summary>The Azure SQL connection failed for another reason.</summary>
    public const string SqlFailed = "ACD-SQL-FAILED";

    /// <summary>The identity is not authorised on the Service Bus entity.</summary>
    public const string ServiceBusUnauthorized = "ACD-SB-UNAUTHORIZED";

    /// <summary>The Service Bus queue or topic does not exist.</summary>
    public const string ServiceBusEntityNotFound = "ACD-SB-ENTITY-NOT-FOUND";

    /// <summary>The AMQP port appears to be blocked.</summary>
    public const string ServiceBusAmqpBlocked = "ACD-SB-AMQP-BLOCKED";

    /// <summary>The Service Bus link failed for another reason.</summary>
    public const string ServiceBusFailed = "ACD-SB-FAILED";

    /// <summary>Public network access is disabled and no private endpoint exists.</summary>
    public const string AzureNoIngressPath = "ACD-AZURE-NO-INGRESS-PATH";

    /// <summary>Public access is disabled but DNS still returns public addresses.</summary>
    public const string AzurePrivateDnsMissing = "ACD-AZURE-PRIVATE-DNS-MISSING";

    /// <summary>Every stage that ran succeeded.</summary>
    public const string NoIssueDetected = "ACD-NO-ISSUE-DETECTED";
}
