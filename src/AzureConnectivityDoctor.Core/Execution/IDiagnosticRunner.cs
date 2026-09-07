using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Execution;

/// <summary>Runs every configured stage against every configured endpoint.</summary>
public interface IDiagnosticRunner
{
    /// <summary>Executes the whole diagnostic run.</summary>
    /// <param name="cancellationToken">Cancels the run cooperatively.</param>
    /// <returns>The completed report. A cancelled run still returns a partial report.</returns>
    Task<RunReport> RunAsync(CancellationToken cancellationToken);
}
