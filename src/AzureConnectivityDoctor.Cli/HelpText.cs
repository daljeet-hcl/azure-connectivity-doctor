namespace AzureConnectivityDoctor.Cli;

/// <summary>The text shown by <c>--help</c>.</summary>
internal static class HelpText
{
    /// <summary>The one-line reminder printed after a usage error.</summary>
    internal const string ShortUsage =
        "Run 'azure-connectivity-doctor --help' for the full list of options.";

    /// <summary>The full help screen.</summary>
    internal const string Usage = """
        azure-connectivity-doctor - diagnose outbound connectivity from the current environment.

        USAGE
          azure-connectivity-doctor <endpoint> [<endpoint> ...] [options]

        ENDPOINT FORMATS
          https://example.com/health          HTTP or HTTPS URL
          example.com:8443                    host and explicit port
          example.com                         host with an inferred default port
          [2603:1000::1]:443                  IPv6 literal with a port
          myserver.database.windows.net       Azure SQL logical server (port 1433)
          myns.servicebus.windows.net         Azure Service Bus namespace (port 5671)

        OPTIONS
          --endpoint <value>        Add an endpoint. May be repeated. Bare arguments work too.
          --endpoints-file <path>   Read endpoints from a file, one per line. '#' starts a comment.
          --timeout <seconds>       Per-stage timeout. Default 10.
          --overall-timeout <sec>   Budget for the whole run. 0 disables it. Default 300.
          --concurrency <count>     How many endpoints to probe at once. Default 4.
          --http                    Send an HTTP request to HTTP and HTTPS endpoints.
          --identity                Acquire Microsoft Entra ID tokens and run authenticated probes.
          --azure-assessment        Read read-only Azure Resource Manager metadata.
          --resource-id <id>        An Azure resource ID to assess. May be repeated.
          --tenant-id <id>          Restrict token acquisition to one tenant.
          --client-id <id>          Client ID of a user-assigned managed identity.
          --json <path>             Write the JSON report to <path>. Default connectivity-report.json.
          --no-json                 Do not write a JSON report.
          --markdown <path>         Write the Markdown report to <path>. Default connectivity-report.md.
          --no-markdown             Do not write a Markdown report.
          --quiet                   Do not print the Markdown report to standard output.
          --verbose                 Print debug-level progress logs to standard error.
          --version                 Print the tool version and exit.
          -h, --help                Print this help and exit.

        EXIT CODES
          0  No error-severity findings.
          1  At least one endpoint produced an error-severity finding.
          2  The command line was invalid.
          3  The run was cancelled by Ctrl+C or by the overall timeout.
          4  The tool failed unexpectedly.

        AUTHENTICATION
          The tool never takes a password, key or connection string on the command line.
          Authenticated probes use Azure.Identity DefaultAzureCredential, which reads managed
          identity, workload identity, environment variables or a signed-in developer session.
          Interactive browser sign-in is disabled so the tool fails fast on headless hosts.

        EXAMPLES
          azure-connectivity-doctor https://contoso.azurewebsites.net --http
          azure-connectivity-doctor myserver.database.windows.net --identity
          azure-connectivity-doctor --endpoints-file samples/endpoints.txt --json report.json

        """;
}
