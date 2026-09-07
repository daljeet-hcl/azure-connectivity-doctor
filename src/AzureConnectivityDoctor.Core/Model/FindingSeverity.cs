namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// How serious a <see cref="Finding"/> is for the caller.
/// </summary>
/// <remarks>
/// The process exit code is derived from the highest severity present in the run. See
/// <c>docs/usage.md</c> for the exit-code contract that scripts and pipelines depend on.
/// </remarks>
public enum FindingSeverity
{
    /// <summary>Contextual information. Never affects the exit code.</summary>
    Information = 0,

    /// <summary>Something worth attention that did not break connectivity.</summary>
    Warning = 1,

    /// <summary>Connectivity to the target is broken.</summary>
    Error = 2
}
