using System.Globalization;
using System.Text;
using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Reporting;

/// <summary>
/// Renders the run as Markdown for a human reader.
/// </summary>
/// <remarks>
/// The document is ordered for someone under pressure: what is wrong, why the tool believes
/// it, what to do about it, and only then the raw evidence. Markdown is used because it is
/// readable as plain text in a terminal and renders as a formatted document when pasted into
/// an issue, a pull request or a chat channel.
/// </remarks>
public sealed class MarkdownReportRenderer : IReportRenderer
{
    /// <inheritdoc />
    public ReportFormat Format => ReportFormat.Markdown;

    /// <inheritdoc />
    public string Render(RunReport report)
    {
        ArgumentNullException.ThrowIfNull(report);

        var builder = new StringBuilder(8 * 1024);

        WriteHeader(builder, report);
        WriteSummaryTable(builder, report);

        foreach (TargetReport target in report.Targets)
        {
            WriteTarget(builder, target);
        }

        WriteAzureAssessment(builder, report);
        WriteFooter(builder);

        return builder.ToString();
    }

    private static void WriteHeader(StringBuilder builder, RunReport report)
    {
        builder.AppendLine("# Azure Connectivity Doctor report");
        builder.AppendLine();
        builder.AppendLine(Invariant($"- **Tool version:** {report.ToolVersion}"));
        builder.AppendLine(Invariant($"- **Schema version:** {report.SchemaVersion}"));
        builder.AppendLine(Invariant($"- **Started (UTC):** {report.StartedUtc:u}"));
        builder.AppendLine(Invariant($"- **Completed (UTC):** {report.CompletedUtc:u}"));
        builder.AppendLine(Invariant($"- **Duration:** {report.DurationMilliseconds:F0} ms"));
        builder.AppendLine(Invariant($"- **Overall severity:** {report.HighestSeverity}"));

        if (report.Cancelled)
        {
            builder.AppendLine("- **Cancelled:** yes — the results below are incomplete");
        }

        builder.AppendLine();
        builder.AppendLine("## Where this was measured from");
        builder.AppendLine();
        builder.AppendLine("The same endpoint can be reachable from one environment and unreachable from");
        builder.AppendLine("another. These results describe this environment only.");
        builder.AppendLine();
        builder.AppendLine(Invariant($"- **Detected platform:** {report.Runtime.DetectedPlatform}"));
        builder.AppendLine(Invariant($"- **Operating system:** {report.Runtime.OperatingSystem}"));
        builder.AppendLine(Invariant($"- **Architecture:** {report.Runtime.ProcessArchitecture}"));
        builder.AppendLine(Invariant($"- **.NET runtime:** {report.Runtime.FrameworkDescription}"));
        builder.AppendLine();
    }

    private static void WriteSummaryTable(StringBuilder builder, RunReport report)
    {
        builder.AppendLine("## Summary");
        builder.AppendLine();

        if (report.Targets.Count == 0)
        {
            builder.AppendLine("No endpoints were diagnosed.");
            builder.AppendLine();
            return;
        }

        builder.AppendLine("| Endpoint | Severity | Primary finding |");
        builder.AppendLine("| --- | --- | --- |");

        foreach (TargetReport target in report.Targets)
        {
            Finding? primary = target.Findings.Count > 0 ? target.Findings[0] : null;
            string name = target.Target?.DisplayName ?? target.RawValue;
            string finding = primary is null
                ? "(no findings)"
                : Invariant($"`{primary.Code}` {primary.Title}");

            builder.AppendLine(Invariant(
                $"| {Escape(name)} | {target.HighestSeverity} | {Escape(finding)} |"));
        }

        builder.AppendLine();
    }

    private static void WriteTarget(StringBuilder builder, TargetReport target)
    {
        string name = target.Target?.DisplayName ?? target.RawValue;

        builder.AppendLine(Invariant($"## {Escape(name)}"));
        builder.AppendLine();
        builder.AppendLine(Invariant($"Supplied as `{target.RawValue}`."));

        if (target.Target is not null)
        {
            builder.AppendLine();
            builder.AppendLine(Invariant($"- **Service kind:** {target.Target.ServiceKind}"));
            builder.AppendLine(Invariant($"- **Host:** `{target.Target.Host}`"));
            builder.AppendLine(Invariant($"- **Port:** {target.Target.Port}"));
            builder.AppendLine(Invariant(
                $"- **TLS on connect:** {(target.Target.TlsOnConnect ? "yes" : "no")}"));

            if (target.Target.DatabaseName is not null)
            {
                builder.AppendLine(Invariant($"- **Database:** `{target.Target.DatabaseName}`"));
            }

            if (target.Target.EntityName is not null)
            {
                builder.AppendLine(Invariant($"- **Entity:** `{target.Target.EntityName}`"));
            }
        }

        builder.AppendLine();
        WriteFindings(builder, target.Findings);
        WriteStages(builder, target.Stages);
    }

    private static void WriteFindings(StringBuilder builder, IReadOnlyList<Finding> findings)
    {
        builder.AppendLine("### Findings");
        builder.AppendLine();

        if (findings.Count == 0)
        {
            builder.AppendLine("No findings were produced for this endpoint.");
            builder.AppendLine();
            return;
        }

        foreach (Finding finding in findings)
        {
            builder.AppendLine(Invariant(
                $"#### {SeverityIcon(finding.Severity)} `{finding.Code}` — {Escape(finding.Title)}"));
            builder.AppendLine();
            builder.AppendLine(Invariant(
                $"**Severity:** {finding.Severity}   **Confidence:** {finding.Confidence}"));
            builder.AppendLine();
            builder.AppendLine(Escape(finding.Rationale));
            builder.AppendLine();

            if (finding.BasedOnStages.Count > 0)
            {
                builder.AppendLine(Invariant(
                    $"**Based on:** {string.Join(", ", finding.BasedOnStages)}"));
                builder.AppendLine();
            }

            if (finding.RecommendedActions.Count > 0)
            {
                builder.AppendLine("**Recommended actions**");
                builder.AppendLine();

                int index = 1;
                foreach (string action in finding.RecommendedActions)
                {
                    builder.AppendLine(Invariant($"{index}. {Escape(action)}"));
                    index++;
                }

                builder.AppendLine();
            }
        }
    }

    private static void WriteStages(StringBuilder builder, IReadOnlyList<StageResult> stages)
    {
        builder.AppendLine("### Evidence");
        builder.AppendLine();

        if (stages.Count == 0)
        {
            builder.AppendLine("No stages ran for this endpoint.");
            builder.AppendLine();
            return;
        }

        foreach (StageResult stage in stages)
        {
            builder.AppendLine(Invariant(
                $"#### {stage.Stage} — {stage.Outcome} ({stage.DurationMilliseconds:F0} ms)"));
            builder.AppendLine();
            builder.AppendLine(Escape(stage.Summary));
            builder.AppendLine();

            if (stage.ErrorType is not null)
            {
                builder.AppendLine(Invariant($"**Error type:** `{stage.ErrorType}`"));
                builder.AppendLine();
            }

            if (stage.ErrorMessage is not null)
            {
                builder.AppendLine("```text");
                builder.AppendLine(stage.ErrorMessage);
                builder.AppendLine("```");
                builder.AppendLine();
            }

            if (stage.Evidence.Count == 0)
            {
                continue;
            }

            builder.AppendLine("| Fact | Value |");
            builder.AppendLine("| --- | --- |");

            foreach (KeyValuePair<string, string> item in stage.Evidence.OrderBy(
                pair => pair.Key,
                StringComparer.Ordinal))
            {
                builder.AppendLine(Invariant($"| `{item.Key}` | {Escape(item.Value)} |"));
            }

            builder.AppendLine();
        }
    }

    private static void WriteAzureAssessment(StringBuilder builder, RunReport report)
    {
        if (report.AzureAssessment.Count == 0)
        {
            return;
        }

        builder.AppendLine("## Azure resource assessment (read-only)");
        builder.AppendLine();
        builder.AppendLine("These facts were read from the Azure control plane with HTTP GET requests only.");
        builder.AppendLine("Nothing was created, changed or deleted.");
        builder.AppendLine();

        WriteStages(builder, report.AzureAssessment);
    }

    private static void WriteFooter(StringBuilder builder)
    {
        builder.AppendLine("---");
        builder.AppendLine();
        builder.AppendLine("Generated by Azure Connectivity Doctor. Values that looked like secrets were");
        builder.AppendLine("redacted before this report was written. Review the report before sharing it,");
        builder.AppendLine("because host names and certificate subjects can still be sensitive.");
    }

    private static string SeverityIcon(FindingSeverity severity)
    {
        return severity switch
        {
            FindingSeverity.Error => "❌",
            FindingSeverity.Warning => "⚠️",
            _ => "ℹ️"
        };
    }

    /// <summary>
    /// Neutralises the characters that would break a Markdown table cell.
    /// </summary>
    /// <remarks>
    /// Evidence values contain certificate subjects and error messages, which routinely include
    /// pipes and newlines. Escaping them keeps the table intact without altering the meaning.
    /// </remarks>
    internal static string Escape(string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value
            .Replace("\r\n", " ", StringComparison.Ordinal)
            .Replace("\n", " ", StringComparison.Ordinal)
            .Replace("\r", " ", StringComparison.Ordinal)
            .Replace("|", "\\|", StringComparison.Ordinal);
    }

    private static string Invariant(FormattableString text)
    {
        return FormattableString.Invariant(text);
    }
}
