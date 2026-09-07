using System.Net;
using AzureConnectivityDoctor.Core.Analysis;
using AzureConnectivityDoctor.Core.Endpoints;
using AzureConnectivityDoctor.Core.Execution;
using AzureConnectivityDoctor.Core.Identity;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Options;
using AzureConnectivityDoctor.Core.Tests.Fakes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AzureConnectivityDoctor.Core.Tests;

/// <summary>Covers the stage gating and ordering performed by the runner.</summary>
public sealed class DiagnosticRunnerTests
{
    [Fact]
    public async Task RunAsync_PreservesTheOrderOfTheSuppliedEndpoints()
    {
        DiagnosticRunner runner = BuildRunner(
            new DoctorOptions
            {
                Endpoints = ["a.example.com:443", "b.example.com:443", "c.example.com:443"],
                MaxConcurrency = 3,
                JsonOutputPath = null,
                MarkdownOutputPath = null
            });

        RunReport report = await runner.RunAsync(TestContext.Current.CancellationToken);

        Assert.Equal(
            ["a.example.com:443", "b.example.com:443", "c.example.com:443"],
            report.Targets.Select(target => target.RawValue));
    }

    [Fact]
    public async Task RunAsync_DoesNotAttemptTcpWhenDnsReturnedNoAddresses()
    {
        var tcpProbe = new StubTcpProbe(new TcpProbeResult(Succeeded(DiagnosticStage.TcpConnect), null));

        DiagnosticRunner runner = BuildRunner(
            new DoctorOptions { Endpoints = ["example.com:443"] },
            dnsProbe: new StubDnsProbe(new DnsProbeResult(
                new StageResult
                {
                    Stage = DiagnosticStage.DnsResolution,
                    Outcome = DiagnosticOutcome.Failed,
                    Summary = "The host name could not be resolved."
                },
                [])),
            tcpProbe: tcpProbe);

        RunReport report = await runner.RunAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, tcpProbe.CallCount);
        StageResult tcp = Stage(report, DiagnosticStage.TcpConnect);
        Assert.Equal(DiagnosticOutcome.NotAttempted, tcp.Outcome);
    }

    [Fact]
    public async Task RunAsync_SkipsTlsForAzureSqlBecauseTdsUpgradesLater()
    {
        var tlsProbe = new StubTlsProbe(new TlsProbeResult(
            Succeeded(DiagnosticStage.TlsHandshake),
            Succeeded(DiagnosticStage.CertificateValidation)));

        DiagnosticRunner runner = BuildRunner(
            new DoctorOptions { Endpoints = ["contoso.database.windows.net"] },
            tlsProbe: tlsProbe);

        RunReport report = await runner.RunAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, tlsProbe.CallCount);
        Assert.Equal(DiagnosticOutcome.Skipped, Stage(report, DiagnosticStage.TlsHandshake).Outcome);
        Assert.Equal(DiagnosticOutcome.Skipped, Stage(report, DiagnosticStage.CertificateValidation).Outcome);
    }

    [Fact]
    public async Task RunAsync_SkipsHttpUnlessItWasEnabled()
    {
        var httpProbe = new StubHttpProbe(Succeeded(DiagnosticStage.HttpRequest));

        DiagnosticRunner runner = BuildRunner(
            new DoctorOptions { Endpoints = ["https://example.com"], EnableHttp = false },
            httpProbe: httpProbe);

        RunReport report = await runner.RunAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, httpProbe.CallCount);
        Assert.Equal(DiagnosticOutcome.Skipped, Stage(report, DiagnosticStage.HttpRequest).Outcome);
    }

    [Fact]
    public async Task RunAsync_RunsHttpWhenEnabledAndTcpSucceeded()
    {
        var httpProbe = new StubHttpProbe(Succeeded(DiagnosticStage.HttpRequest));

        DiagnosticRunner runner = BuildRunner(
            new DoctorOptions { Endpoints = ["https://example.com"], EnableHttp = true },
            httpProbe: httpProbe);

        RunReport report = await runner.RunAsync(TestContext.Current.CancellationToken);

        Assert.Equal(1, httpProbe.CallCount);
        Assert.Equal(DiagnosticOutcome.Succeeded, Stage(report, DiagnosticStage.HttpRequest).Outcome);
    }

    [Fact]
    public async Task RunAsync_RequestsTheSqlScopeForAnAzureSqlEndpoint()
    {
        var tokenProbe = new StubTokenProbe(new TokenProbeResult(
            Succeeded(DiagnosticStage.IdentityTokenAcquisition),
            "token"));

        DiagnosticRunner runner = BuildRunner(
            new DoctorOptions { Endpoints = ["contoso.database.windows.net"], EnableIdentity = true },
            tokenProbe: tokenProbe);

        RunReport report = await runner.RunAsync(TestContext.Current.CancellationToken);

        Assert.Equal("https://database.windows.net/.default", tokenProbe.LastScope);
        Assert.Equal(DiagnosticOutcome.Succeeded, Stage(report, DiagnosticStage.SqlConnection).Outcome);
    }

    [Fact]
    public async Task RunAsync_RecordsAFailedParseWithoutRunningAnyProbe()
    {
        var dnsProbe = new StubDnsProbe(new DnsProbeResult(Succeeded(DiagnosticStage.DnsResolution), []));

        DiagnosticRunner runner = BuildRunner(
            new DoctorOptions { Endpoints = ["https://user:secret@example.com"] },
            dnsProbe: dnsProbe);

        RunReport report = await runner.RunAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, dnsProbe.CallCount);
        Assert.Null(report.Targets[0].Target);
        Assert.Equal(FindingSeverity.Error, report.HighestSeverity);
        Assert.DoesNotContain("secret", report.Targets[0].Stages[0].Evidence["rawValue"], StringComparison.Ordinal);
    }

    [Fact]
    public async Task RunAsync_SkipsTheAzureAssessmentWhenItIsDisabled()
    {
        var assessor = new StubAzureAssessor(Succeeded(DiagnosticStage.AzureResourceAssessment));

        DiagnosticRunner runner = BuildRunner(
            new DoctorOptions { Endpoints = ["example.com:443"], EnableAzureAssessment = false },
            azureAssessor: assessor);

        RunReport report = await runner.RunAsync(TestContext.Current.CancellationToken);

        Assert.Equal(0, assessor.CallCount);
        Assert.Equal(DiagnosticOutcome.Skipped, report.AzureAssessment[0].Outcome);
    }

    [Fact]
    public async Task RunAsync_ReturnsACancelledReportWhenTheTokenIsAlreadyCancelled()
    {
        DiagnosticRunner runner = BuildRunner(new DoctorOptions { Endpoints = ["example.com:443"] });

        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        RunReport report = await runner.RunAsync(cancellation.Token);

        Assert.True(report.Cancelled);
    }

    private static StageResult Stage(RunReport report, DiagnosticStage stage)
    {
        return report.Targets[0].Stages.Single(result => result.Stage == stage);
    }

    private static StageResult Succeeded(DiagnosticStage stage)
    {
        return new StageResult
        {
            Stage = stage,
            Outcome = DiagnosticOutcome.Succeeded,
            Summary = "The stage succeeded."
        };
    }

    private static DiagnosticRunner BuildRunner(
        DoctorOptions options,
        StubDnsProbe? dnsProbe = null,
        StubTcpProbe? tcpProbe = null,
        StubTlsProbe? tlsProbe = null,
        StubHttpProbe? httpProbe = null,
        StubTokenProbe? tokenProbe = null,
        StubAzureAssessor? azureAssessor = null)
    {
        IPAddress address = IPAddress.Parse("93.184.216.34");

        return new DiagnosticRunner(
            Microsoft.Extensions.Options.Options.Create(options),
            new EndpointParser(),
            dnsProbe ?? new StubDnsProbe(new DnsProbeResult(Succeeded(DiagnosticStage.DnsResolution), [address])),
            tcpProbe ?? new StubTcpProbe(new TcpProbeResult(Succeeded(DiagnosticStage.TcpConnect), address)),
            tlsProbe ?? new StubTlsProbe(new TlsProbeResult(
                Succeeded(DiagnosticStage.TlsHandshake),
                Succeeded(DiagnosticStage.CertificateValidation))),
            httpProbe ?? new StubHttpProbe(Succeeded(DiagnosticStage.HttpRequest)),
            tokenProbe ?? new StubTokenProbe(new TokenProbeResult(
                Succeeded(DiagnosticStage.IdentityTokenAcquisition),
                "token")),
            new StubSqlProbe(Succeeded(DiagnosticStage.SqlConnection)),
            new StubServiceBusProbe(Succeeded(DiagnosticStage.ServiceBusLink)),
            azureAssessor ?? new StubAzureAssessor(Succeeded(DiagnosticStage.AzureResourceAssessment)),
            new RootCauseAnalyzer(),
            TimeProvider.System,
            NullLogger<DiagnosticRunner>.Instance);
    }
}
