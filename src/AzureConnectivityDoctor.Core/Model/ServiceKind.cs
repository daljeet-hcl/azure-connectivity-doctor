namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// The kind of service behind an endpoint, which decides the protocol-aware probes to run.
/// </summary>
public enum ServiceKind
{
    /// <summary>A plain TCP endpoint with no protocol-specific handling.</summary>
    GenericTcp = 0,

    /// <summary>An HTTP or HTTPS endpoint.</summary>
    Http = 1,

    /// <summary>An Azure SQL Database or SQL Managed Instance endpoint.</summary>
    AzureSql = 2,

    /// <summary>An Azure Service Bus namespace endpoint.</summary>
    AzureServiceBus = 3
}
