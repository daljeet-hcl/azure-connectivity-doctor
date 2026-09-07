using System.Text.Json;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Reporting;
using Xunit;

namespace AzureConnectivityDoctor.Core.Tests;

/// <summary>Covers both report renderers.</summary>
public sealed class ReportRendererTests
{
    [Fact]
    public void MarkdownRenderer_DeclaresTheMarkdownFormat()
    {
        Assert.Equal(ReportFormat.Markdown, new MarkdownReportRenderer().Format);
    }

    [Fact]
    public void JsonRenderer_DeclaresTheJsonFormat()
    {
        Assert.Equal(ReportFormat.Json, new JsonReportRenderer().Format);
    }

    [Fact]
    public void MarkdownRenderer_IncludesTheTargetAndTheFinding()
    {
        string markdown = new MarkdownReportRenderer().Render(BuildReport());

        Assert.Contains("example.com:443", markdown, StringComparison.Ordinal);
        Assert.Contains("ACD-TCP-BLOCKED", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public void JsonRenderer_ProducesParseableJsonContainingTheSchemaVersion()
    {
        string json = new JsonReportRenderer().Render(BuildReport());

        using JsonDocument document = JsonDocument.Parse(json);

        Assert.Equal(JsonValueKind.Object, document.RootElement.ValueKind);
        Assert.Contains("\"1.0\"", json, StringComparison.Ordinal);
        Assert.Contains("ACD-TCP-BLOCKED", json, StringComparison.Ordinal);
    }

    [Fact]
    public void JsonRenderer_DoesNotLeakSecretsPresentInEvidence()
    {
        RunReport report = BuildReport("Server=x;Password=hunter2;");

        string json = new JsonReportRenderer().Render(report);

        Assert.DoesNotContain("hunter2", json, StringComparison.Ordinal);
    }

    [Fact]
    public void MarkdownRenderer_DoesNotLeakSecretsPresentInEvidence()
    {
        RunReport report = BuildReport("Server=x;Password=hunter2;");

        string markdown = new MarkdownReportRenderer().Render(report);

        Assert.DoesNotContain("hunter2", markdown, StringComparison.Ordinal);
    }

    private static RunReport BuildReport(string? secretEvidence = null)
    {
        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["socketError"] = "TimedOut"
        };

        if (secretEvidence is not null)
        {
            evidence["connectionString"] = secretEvidence;
        }

        var target = new ProbeTarget
        {
            RawValue = "example.com:443",
            Host = "example.com",
            Port = 443,
            ServiceKind = ServiceKind.GenericTcp,
            TlsOnConnect = true,
            HostIsIpLiteral = false
        };

        return new RunReport
        {
            ToolVersion = "1.0.0",
            StartedUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            CompletedUtc = new DateTimeOffset(2026, 1, 1, 0, 0, 5, TimeSpan.Zero),
            Runtime = new RuntimeContext
            {
                OperatingSystem = "Linux",
                ProcessArchitecture = "X64",
                FrameworkDescription = ".NET 10.0.0",
                DetectedPlatform = "GitHubActions"
            },
            Targets =
            [
                new TargetReport
                {
                    RawValue = "example.com:443",
                    Target = target,
                    Stages =
                    [
                        new StageResult
                        {
                            Stage = DiagnosticStage.TcpConnect,
                            Outcome = DiagnosticOutcome.Failed,
                            Summary = "The connection timed out.",
                            Evidence = evidence
                        }
                    ],
                    Findings =
                    [
                        new Finding
                        {
                            Code = "ACD-TCP-BLOCKED",
                            Title = "Outbound traffic on this port is being dropped",
                            Severity = FindingSeverity.Error,
                            Confidence = EvidenceConfidence.Observed,
                            Rationale = "No reply of any kind arrived.",
                            BasedOnStages = [DiagnosticStage.TcpConnect],
                            RecommendedActions = ["Check outbound firewall rules."]
                        }
                    ]
                }
            ]
        };
    }
}
