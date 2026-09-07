namespace AzureConnectivityDoctor.Cli;

/// <summary>
/// The process exit codes. These are a public contract that scripts and pipelines depend on.
/// </summary>
/// <remarks>
/// The contract is documented in <c>docs/usage.md</c>. Never reuse or renumber a value; add a
/// new one instead.
/// </remarks>
internal static class ExitCodes
{
    /// <summary>Every target was reachable, or only informational findings were produced.</summary>
    internal const int Success = 0;

    /// <summary>At least one target produced an error-severity finding.</summary>
    internal const int ConnectivityFailure = 1;

    /// <summary>The command line was invalid.</summary>
    internal const int UsageError = 2;

    /// <summary>The run was cancelled by Ctrl+C or by the overall timeout.</summary>
    internal const int Cancelled = 3;

    /// <summary>The tool itself failed unexpectedly.</summary>
    internal const int InternalError = 4;
}
