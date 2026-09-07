using System.Globalization;
using System.Net;
using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Endpoints;

/// <summary>
/// The default <see cref="IEndpointParser"/>.
/// </summary>
/// <remarks>
/// <para>Accepted forms, in the order they are tried:</para>
/// <list type="bullet">
///   <item><description><c>scheme://host[:port][/path]</c> — for example <c>https://api.example.com/health</c></description></item>
///   <item><description><c>host:port</c> — for example <c>10.0.0.4:5432</c></description></item>
///   <item><description><c>host</c> — the port is then inferred from the recognised service</description></item>
///   <item><description><c>[ipv6]:port</c> — for example <c>[2603:1010::1]:443</c></description></item>
/// </list>
/// <para>
/// The parser is intentionally strict about one thing: it rejects any input containing user
/// information (<c>user:password@host</c>). Accepting it would invite operators to paste
/// credentials onto a command line where they land in shell history and process listings.
/// </para>
/// </remarks>
public sealed class EndpointParser : IEndpointParser
{
    private const int DefaultSqlPort = 1433;
    private const int DefaultAmqpsPort = 5671;
    private const int DefaultHttpPort = 80;
    private const int DefaultHttpsPort = 443;

    // Suffixes of Azure SQL endpoints across the public and sovereign clouds.
    private static readonly string[] SqlHostSuffixes =
    [
        ".database.windows.net",
        ".database.chinacloudapi.cn",
        ".database.usgovcloudapi.net",
        ".database.cloudapi.de"
    ];

    // Suffixes of Azure Service Bus endpoints across the public and sovereign clouds.
    private static readonly string[] ServiceBusHostSuffixes =
    [
        ".servicebus.windows.net",
        ".servicebus.chinacloudapi.cn",
        ".servicebus.usgovcloudapi.net",
        ".servicebus.cloudapi.de"
    ];

    /// <inheritdoc />
    public TargetParseResult Parse(string value)
    {
        string input = (value ?? string.Empty).Trim();
        if (input.Length == 0)
        {
            return TargetParseResult.Failure("The endpoint is empty.");
        }

        if (input.Contains('@', StringComparison.Ordinal))
        {
            return TargetParseResult.Failure(
                "The endpoint contains user information ('@'). Credentials must never be passed " +
                "on the command line. Supply only the host, and authenticate with --identity.");
        }

        string? scheme = null;
        string remainder = input;

        int schemeSeparator = input.IndexOf("://", StringComparison.Ordinal);
        if (schemeSeparator > 0)
        {
            scheme = input[..schemeSeparator].ToLowerInvariant();
            remainder = input[(schemeSeparator + 3)..];
        }

        if (remainder.Length == 0)
        {
            return TargetParseResult.Failure("The endpoint has a scheme but no host.");
        }

        // Split the authority from the path. The path is only meaningful for HTTP and Service Bus.
        string authority = remainder;
        string path = string.Empty;
        int pathSeparator = remainder.IndexOf('/', StringComparison.Ordinal);
        if (pathSeparator >= 0)
        {
            authority = remainder[..pathSeparator];
            path = remainder[pathSeparator..];
        }

        if (!TrySplitAuthority(authority, out string host, out int? explicitPort, out string? authorityError))
        {
            return TargetParseResult.Failure(authorityError!);
        }

        if (host.Length == 0)
        {
            return TargetParseResult.Failure("The endpoint has no host.");
        }

        bool hostIsIpLiteral = IPAddress.TryParse(host, out _);
        ServiceKind serviceKind = DetermineServiceKind(scheme, host);

        int? defaultPort = DetermineDefaultPort(scheme, serviceKind);
        int? port = explicitPort ?? defaultPort;
        if (port is null)
        {
            return TargetParseResult.Failure(
                $"No port was supplied for '{input}' and none could be inferred. " +
                "Write the endpoint as host:port, for example 'db.internal:5432'.");
        }

        if (port is < 1 or > 65535)
        {
            return TargetParseResult.Failure(
                string.Create(CultureInfo.InvariantCulture, $"Port {port} is outside the valid range 1-65535."));
        }

        bool tlsOnConnect = DetermineTlsOnConnect(scheme, serviceKind, port.Value);

        Uri? httpUri = null;
        if (serviceKind == ServiceKind.Http)
        {
            string effectiveScheme = scheme ?? (port.Value == DefaultHttpPort ? "http" : "https");
            string hostForUri = host.Contains(':', StringComparison.Ordinal) ? "[" + host + "]" : host;
            string effectivePath = path.Length == 0 ? "/" : path;
            string candidate = string.Create(
                CultureInfo.InvariantCulture,
                $"{effectiveScheme}://{hostForUri}:{port.Value}{effectivePath}");

            if (!Uri.TryCreate(candidate, UriKind.Absolute, out httpUri))
            {
                return TargetParseResult.Failure($"'{input}' could not be turned into a valid absolute URI.");
            }
        }

        string? entityName = null;
        string? databaseName = null;
        string trimmedPath = path.TrimStart('/').TrimEnd('/');

        if (serviceKind == ServiceKind.AzureServiceBus && trimmedPath.Length > 0)
        {
            entityName = trimmedPath;
        }

        if (serviceKind == ServiceKind.AzureSql && trimmedPath.Length > 0)
        {
            databaseName = trimmedPath;
        }

        var target = new ProbeTarget
        {
            RawValue = input,
            Host = host,
            Port = port.Value,
            ServiceKind = serviceKind,
            TlsOnConnect = tlsOnConnect,
            HttpUri = httpUri,
            EntityName = entityName,
            DatabaseName = databaseName,
            HostIsIpLiteral = hostIsIpLiteral
        };

        return TargetParseResult.Success(target);
    }

    /// <summary>
    /// Splits <c>host:port</c>, <c>host</c> or <c>[ipv6]:port</c> into its parts.
    /// </summary>
    private static bool TrySplitAuthority(
        string authority,
        out string host,
        out int? port,
        out string? error)
    {
        host = string.Empty;
        port = null;
        error = null;

        if (authority.StartsWith('['))
        {
            int closingBracket = authority.IndexOf(']', StringComparison.Ordinal);
            if (closingBracket < 0)
            {
                error = $"'{authority}' opens an IPv6 literal with '[' but never closes it with ']'.";
                return false;
            }

            host = authority[1..closingBracket];
            string tail = authority[(closingBracket + 1)..];
            if (tail.Length == 0)
            {
                return true;
            }

            if (!tail.StartsWith(':'))
            {
                error = $"Unexpected text '{tail}' after the IPv6 literal in '{authority}'.";
                return false;
            }

            return TryParsePort(tail[1..], authority, out port, out error);
        }

        int lastColon = authority.LastIndexOf(':');
        if (lastColon < 0)
        {
            host = authority;
            return true;
        }

        // More than one colon and no brackets means a bare IPv6 address such as "::1".
        if (authority.IndexOf(':', StringComparison.Ordinal) != lastColon)
        {
            if (IPAddress.TryParse(authority, out _))
            {
                host = authority;
                return true;
            }

            error = $"'{authority}' contains several colons. Wrap IPv6 addresses in brackets, for example [::1]:443.";
            return false;
        }

        host = authority[..lastColon];
        return TryParsePort(authority[(lastColon + 1)..], authority, out port, out error);
    }

    private static bool TryParsePort(string text, string authority, out int? port, out string? error)
    {
        port = null;
        error = null;

        if (text.Length == 0)
        {
            error = $"'{authority}' ends with ':' but no port number follows it.";
            return false;
        }

        if (!int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed))
        {
            error = $"'{text}' in '{authority}' is not a valid port number.";
            return false;
        }

        port = parsed;
        return true;
    }

    private static ServiceKind DetermineServiceKind(string? scheme, string host)
    {
        if (EndsWithAny(host, SqlHostSuffixes))
        {
            return ServiceKind.AzureSql;
        }

        if (EndsWithAny(host, ServiceBusHostSuffixes))
        {
            return ServiceKind.AzureServiceBus;
        }

        return scheme switch
        {
            "http" or "https" => ServiceKind.Http,
            "sql" or "mssql" or "tds" => ServiceKind.AzureSql,
            "sb" or "amqps" or "amqp" => ServiceKind.AzureServiceBus,
            _ => ServiceKind.GenericTcp
        };
    }

    private static int? DetermineDefaultPort(string? scheme, ServiceKind serviceKind)
    {
        int? fromScheme = scheme switch
        {
            "http" => DefaultHttpPort,
            "https" => DefaultHttpsPort,
            "sql" or "mssql" or "tds" => DefaultSqlPort,
            "sb" or "amqps" => DefaultAmqpsPort,
            "amqp" => 5672,
            "ldaps" => 636,
            "ldap" => 389,
            "smtps" => 465,
            "smtp" => 587,
            "redis" => 6379,
            "postgres" or "postgresql" => 5432,
            "mysql" => 3306,
            _ => null
        };

        if (fromScheme is not null)
        {
            return fromScheme;
        }

        return serviceKind switch
        {
            ServiceKind.AzureSql => DefaultSqlPort,
            ServiceKind.AzureServiceBus => DefaultAmqpsPort,
            ServiceKind.Http => DefaultHttpsPort,
            _ => null
        };
    }

    /// <summary>
    /// Decides whether TLS is negotiated at connection time.
    /// </summary>
    /// <remarks>
    /// Azure SQL is the important exception. TDS starts in the clear and upgrades to TLS during
    /// the PRELOGIN exchange, so an <c>SslStream</c> handshake driven straight at port 1433 will
    /// always fail. Reporting that as a TLS fault would send operators down the wrong path, so
    /// the TLS stage is skipped for Azure SQL and the encryption check is delegated to the SQL
    /// probe, which reads the negotiated encryption state from the driver instead.
    /// </remarks>
    private static bool DetermineTlsOnConnect(string? scheme, ServiceKind serviceKind, int port)
    {
        if (serviceKind == ServiceKind.AzureSql)
        {
            return false;
        }

        if (scheme is "https" or "amqps" or "sb" or "ldaps" or "smtps" or "tls" or "ssl")
        {
            return true;
        }

        if (scheme is "http" or "amqp" or "tcp" or "ldap")
        {
            return false;
        }

        return port is DefaultHttpsPort or DefaultAmqpsPort or 636 or 465 or 993 or 995 or 8443;
    }

    private static bool EndsWithAny(string host, string[] suffixes)
    {
        foreach (string suffix in suffixes)
        {
            if (host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
