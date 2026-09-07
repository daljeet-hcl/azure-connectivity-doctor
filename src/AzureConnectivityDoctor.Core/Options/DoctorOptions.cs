namespace AzureConnectivityDoctor.Core.Options;

/// <summary>
/// Everything the diagnostic run needs to know, assembled from the command line.
/// </summary>
/// <remarks>
/// This type contains no credentials and no secrets by design. Authentication is delegated
/// entirely to <see cref="Azure.Core.TokenCredential"/>, which sources tokens from managed
/// identity, workload identity, environment variables or a signed-in developer session.
/// </remarks>
public sealed class DoctorOptions
{
    /// <summary>The configuration section name, for readers binding this from configuration.</summary>
    public const string SectionName = "Doctor";

    /// <summary>The endpoints to diagnose.</summary>
    public IReadOnlyList<string> Endpoints { get; init; } = [];

    /// <summary>A file containing one endpoint per line, merged with <see cref="Endpoints"/>.</summary>
    public string? EndpointsFile { get; init; }

    /// <summary>Per-stage timeout. Applies to each network operation individually.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>An overall budget for the whole run. Zero means no overall limit.</summary>
    public TimeSpan OverallTimeout { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>How many endpoints may be probed at the same time.</summary>
    public int MaxConcurrency { get; init; } = 4;

    /// <summary>Whether to issue an HTTP request against HTTP and HTTPS endpoints.</summary>
    public bool EnableHttp { get; init; }

    /// <summary>Whether to acquire Microsoft Entra ID tokens and run authenticated probes.</summary>
    public bool EnableIdentity { get; init; }

    /// <summary>Whether to collect read-only Azure Resource Manager metadata.</summary>
    public bool EnableAzureAssessment { get; init; }

    /// <summary>Azure resource IDs to read during the assessment.</summary>
    public IReadOnlyList<string> ResourceIds { get; init; } = [];

    /// <summary>The path of the JSON report to write. Null disables the JSON report.</summary>
    public string? JsonOutputPath { get; init; } = "connectivity-report.json";

    /// <summary>The path of the Markdown report to write. Null disables the Markdown report.</summary>
    public string? MarkdownOutputPath { get; init; } = "connectivity-report.md";

    /// <summary>Whether to print the Markdown report to standard output as well.</summary>
    public bool PrintToConsole { get; init; } = true;

    /// <summary>
    /// The tenant to restrict token acquisition to. Null lets the credential chain decide.
    /// </summary>
    public string? TenantId { get; init; }

    /// <summary>
    /// The client ID of a user-assigned managed identity. Null uses the system-assigned identity.
    /// </summary>
    public string? ManagedIdentityClientId { get; init; }
}
