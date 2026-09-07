namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// The complete diagnostic result for one endpoint.
/// </summary>
public sealed record TargetReport
{
    /// <summary>The exact endpoint text supplied by the operator.</summary>
    public required string RawValue { get; init; }

    /// <summary>The parsed target, or <see langword="null"/> when parsing failed.</summary>
    public ProbeTarget? Target { get; init; }

    /// <summary>Every stage that was considered for this target, in stage order.</summary>
    public IReadOnlyList<StageResult> Stages { get; init; } = [];

    /// <summary>The conclusions drawn for this target.</summary>
    public IReadOnlyList<Finding> Findings { get; init; } = [];

    /// <summary>The highest severity among <see cref="Findings"/>.</summary>
    public FindingSeverity HighestSeverity =>
        Findings.Count == 0 ? FindingSeverity.Information : Findings.Max(finding => finding.Severity);
}
