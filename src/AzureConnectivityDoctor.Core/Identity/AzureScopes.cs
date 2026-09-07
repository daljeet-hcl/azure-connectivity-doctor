namespace AzureConnectivityDoctor.Core.Identity;

/// <summary>
/// Maps a target host to the Microsoft Entra ID scope that a token must be requested for.
/// </summary>
/// <remarks>
/// Scopes differ per sovereign cloud. Requesting a public-cloud scope while running against
/// Azure Government or Azure China produces an authentication failure that looks like a
/// permissions problem but is really a wrong-audience problem, so the mapping is explicit.
/// </remarks>
public static class AzureScopes
{
    /// <summary>The Azure Resource Manager scope for the Azure public cloud.</summary>
    public const string PublicCloudResourceManager = "https://management.azure.com/.default";

    private static readonly (string HostSuffix, string Scope)[] SqlScopes =
    [
        (".database.windows.net", "https://database.windows.net/.default"),
        (".database.usgovcloudapi.net", "https://database.usgovcloudapi.net/.default"),
        (".database.chinacloudapi.cn", "https://database.chinacloudapi.cn/.default"),
        (".database.cloudapi.de", "https://database.cloudapi.de/.default")
    ];

    private static readonly (string HostSuffix, string Scope)[] ServiceBusScopes =
    [
        (".servicebus.windows.net", "https://servicebus.azure.net/.default"),
        (".servicebus.usgovcloudapi.net", "https://servicebus.azure.net/.default"),
        (".servicebus.chinacloudapi.cn", "https://servicebus.azure.net/.default")
    ];

    /// <summary>Returns the token scope for an Azure SQL logical server host.</summary>
    /// <param name="host">The fully qualified server name.</param>
    /// <returns>The scope to request, defaulting to the public cloud scope.</returns>
    public static string ForSql(string host)
    {
        return Match(host, SqlScopes, SqlScopes[0].Scope);
    }

    /// <summary>Returns the token scope for an Azure Service Bus namespace host.</summary>
    /// <param name="host">The fully qualified namespace name.</param>
    /// <returns>The scope to request, defaulting to the public cloud scope.</returns>
    public static string ForServiceBus(string host)
    {
        return Match(host, ServiceBusScopes, ServiceBusScopes[0].Scope);
    }

    private static string Match(string host, (string HostSuffix, string Scope)[] table, string fallback)
    {
        if (string.IsNullOrEmpty(host))
        {
            return fallback;
        }

        foreach ((string suffix, string scope) in table)
        {
            if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return scope;
            }
        }

        return fallback;
    }
}
