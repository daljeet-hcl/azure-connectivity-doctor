using System.Collections.ObjectModel;

namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// The immutable record of one <see cref="DiagnosticStage"/> execution.
/// </summary>
/// <remarks>
/// <see cref="Evidence"/> holds flat key/value facts rather than free text so that the JSON
/// report can be queried by other tools. All values pass through
/// <see cref="Security.SecretRedactor"/> before they reach a report.
/// </remarks>
public sealed record StageResult
{
    private static readonly ReadOnlyDictionary<string, string> EmptyEvidence =
        new(new Dictionary<string, string>(StringComparer.Ordinal));

    /// <summary>The stage this result describes.</summary>
    public required DiagnosticStage Stage { get; init; }

    /// <summary>The outcome of the stage.</summary>
    public required DiagnosticOutcome Outcome { get; init; }

    /// <summary>A one-sentence, human-readable summary of what happened.</summary>
    public required string Summary { get; init; }

    /// <summary>Wall-clock duration of the stage, in milliseconds.</summary>
    public double DurationMilliseconds { get; init; }

    /// <summary>Structured facts observed during the stage.</summary>
    public IReadOnlyDictionary<string, string> Evidence { get; init; } = EmptyEvidence;

    /// <summary>The CLR type name of the exception that ended the stage, when one did.</summary>
    public string? ErrorType { get; init; }

    /// <summary>The redacted exception message, when the stage ended in an exception.</summary>
    public string? ErrorMessage { get; init; }

    /// <summary>Creates a result for a stage that did not run because a prerequisite failed.</summary>
    /// <param name="stage">The stage that could not run.</param>
    /// <param name="reason">Why it could not run.</param>
    /// <returns>A <see cref="DiagnosticOutcome.NotAttempted"/> result.</returns>
    public static StageResult NotAttempted(DiagnosticStage stage, string reason)
    {
        return new StageResult
        {
            Stage = stage,
            Outcome = DiagnosticOutcome.NotAttempted,
            Summary = reason
        };
    }

    /// <summary>Creates a result for a stage that does not apply to the target.</summary>
    /// <param name="stage">The stage that was skipped.</param>
    /// <param name="reason">Why it was skipped.</param>
    /// <returns>A <see cref="DiagnosticOutcome.Skipped"/> result.</returns>
    public static StageResult Skipped(DiagnosticStage stage, string reason)
    {
        return new StageResult
        {
            Stage = stage,
            Outcome = DiagnosticOutcome.Skipped,
            Summary = reason
        };
    }
}
