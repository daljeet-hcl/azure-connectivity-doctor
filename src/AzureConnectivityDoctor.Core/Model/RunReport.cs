namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// The complete result of one invocation of the tool. This is the object serialised to JSON.
/// </summary>
/// <remarks>
/// <see cref="SchemaVersion"/> is part of the tool's public contract. Increment it whenever a
/// consumer of the JSON report could break, and record the change in <c>docs/report-schema.md</c>.
/// </remarks>
public sealed record RunReport
{
    /// <summary>The version of the JSON report contract.</summary>
    public string SchemaVersion { get; init; } = "1.0";

    /// <summary>The informational version of the tool that produced the report.</summary>
    public required string ToolVersion { get; init; }

    /// <summary>When the run started (UTC).</summary>
    public required DateTimeOffset StartedUtc { get; init; }

    /// <summary>When the run finished (UTC).</summary>
    public required DateTimeOffset CompletedUtc { get; init; }

    /// <summary>Total wall-clock duration of the run, in milliseconds.</summary>
    public double DurationMilliseconds => (CompletedUtc - StartedUtc).TotalMilliseconds;

    /// <summary>A description of where the tool ran, used to interpret the results.</summary>
    public required RuntimeContext Runtime { get; init; }

    /// <summary>Whether the run was ended early by Ctrl+C or a timeout.</summary>
    public bool Cancelled { get; init; }

    /// <summary>One entry per endpoint, in the order supplied.</summary>
    public IReadOnlyList<TargetReport> Targets { get; init; } = [];

    /// <summary>Read-only Azure Resource Manager evidence, when the assessment was enabled.</summary>
    public IReadOnlyList<StageResult> AzureAssessment { get; init; } = [];

    /// <summary>The highest severity across every target in the run.</summary>
    public FindingSeverity HighestSeverity =>
        Targets.Count == 0 ? FindingSeverity.Information : Targets.Max(target => target.HighestSeverity);
}

/// <summary>
/// Describes the environment the tool ran in.
/// </summary>
/// <remarks>
/// The same endpoint can be reachable from a laptop and unreachable from an App Service
/// instance, so a report without this context is not actionable. Only non-identifying,
/// non-secret values are captured; the machine name and user name are deliberately omitted.
/// </remarks>
public sealed record RuntimeContext
{
    /// <summary>The operating system description, for example "Linux 6.8.0 #1 SMP".</summary>
    public required string OperatingSystem { get; init; }

    /// <summary>The process architecture, for example "X64".</summary>
    public required string ProcessArchitecture { get; init; }

    /// <summary>The .NET runtime version.</summary>
    public required string FrameworkDescription { get; init; }

    /// <summary>
    /// The detected hosting platform, for example "AzureAppService", "AzureContainerApps",
    /// "Kubernetes", "GitHubActions" or "Unknown".
    /// </summary>
    public required string DetectedPlatform { get; init; }
}
