using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Reporting;

/// <summary>Turns a completed <see cref="RunReport"/> into text.</summary>
public interface IReportRenderer
{
    /// <summary>The format this renderer produces, used to select it at runtime.</summary>
    ReportFormat Format { get; }

    /// <summary>Renders the report.</summary>
    /// <param name="report">The completed run.</param>
    /// <returns>The rendered document.</returns>
    string Render(RunReport report);
}

/// <summary>The output formats the tool can produce.</summary>
public enum ReportFormat
{
    /// <summary>Human-readable Markdown.</summary>
    Markdown = 0,

    /// <summary>Machine-readable JSON.</summary>
    Json = 1
}
