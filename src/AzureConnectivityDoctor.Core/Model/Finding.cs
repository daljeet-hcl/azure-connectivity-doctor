namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// A conclusion drawn by the root-cause analyzer from one or more <see cref="StageResult"/>s.
/// </summary>
/// <remarks>
/// Every finding carries the evidence it was derived from and an explicit confidence level.
/// A reader must always be able to answer "why does the tool believe this?" without reading
/// the source code.
/// </remarks>
public sealed record Finding
{
    /// <summary>A stable machine-readable identifier, for example <c>ACD-TCP-BLOCKED</c>.</summary>
    public required string Code { get; init; }

    /// <summary>A short human-readable title.</summary>
    public required string Title { get; init; }

    /// <summary>How serious the finding is.</summary>
    public required FindingSeverity Severity { get; init; }

    /// <summary>How strongly the evidence supports the finding.</summary>
    public required EvidenceConfidence Confidence { get; init; }

    /// <summary>The reasoning that connects the evidence to the conclusion.</summary>
    public required string Rationale { get; init; }

    /// <summary>The stages whose results were used to reach this conclusion.</summary>
    public IReadOnlyList<DiagnosticStage> BasedOnStages { get; init; } = [];

    /// <summary>Concrete next steps for an operator, in the order they should be tried.</summary>
    public IReadOnlyList<string> RecommendedActions { get; init; } = [];
}
