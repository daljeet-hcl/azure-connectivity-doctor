using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Analysis;

/// <summary>Turns raw stage results into ranked, actionable findings.</summary>
public interface IRootCauseAnalyzer
{
    /// <summary>Analyses one target.</summary>
    /// <param name="target">The parsed target, or <see langword="null"/> when parsing failed.</param>
    /// <param name="stages">Every stage result collected for the target.</param>
    /// <param name="azureAssessment">Run-level Azure Resource Manager evidence, possibly empty.</param>
    /// <returns>The findings, ordered most severe first.</returns>
    IReadOnlyList<Finding> Analyze(
        ProbeTarget? target,
        IReadOnlyList<StageResult> stages,
        IReadOnlyList<StageResult> azureAssessment);
}
