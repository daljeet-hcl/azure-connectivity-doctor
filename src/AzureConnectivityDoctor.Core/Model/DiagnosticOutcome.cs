namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// The outcome of a single <see cref="DiagnosticStage"/>.
/// </summary>
/// <remarks>
/// <see cref="NotAttempted"/> and <see cref="Skipped"/> are deliberately distinct.
/// "Not attempted" means an earlier stage failed so this one could not run and we therefore
/// know nothing about it. "Skipped" means the stage does not apply to this target, or the
/// operator disabled it. Collapsing the two would let the report imply knowledge it does
/// not have.
/// </remarks>
public enum DiagnosticOutcome
{
    /// <summary>The stage completed and everything it checked was correct.</summary>
    Succeeded = 0,

    /// <summary>The stage completed but observed a problem.</summary>
    Failed = 1,

    /// <summary>The stage completed with a partially correct result.</summary>
    Warning = 2,

    /// <summary>The stage does not apply to this target, or was disabled by the operator.</summary>
    Skipped = 3,

    /// <summary>A prerequisite stage failed, so this stage could not run.</summary>
    NotAttempted = 4,

    /// <summary>The stage ran but the evidence gathered does not support a conclusion.</summary>
    Inconclusive = 5
}
