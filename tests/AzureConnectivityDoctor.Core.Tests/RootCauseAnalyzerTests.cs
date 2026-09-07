using System.Globalization;
using AzureConnectivityDoctor.Core.Analysis;
using AzureConnectivityDoctor.Core.Model;
using Xunit;

namespace AzureConnectivityDoctor.Core.Tests;

/// <summary>
/// Covers the correlation rules. The analyzer is a pure function, so every rule is exercised by
/// constructing stage results directly; no network is involved.
/// </summary>
public sealed class RootCauseAnalyzerTests
{
    private readonly RootCauseAnalyzer _analyzer = new();

    [Fact]
    public void Analyze_ReportsNameNotFoundWhenTheResolverAnswersAuthoritatively()
    {
        StageResult dns = Failed(
            DiagnosticStage.DnsResolution,
            "The host name could not be resolved.",
            ("socketError", "HostNotFound"));

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [Ok(DiagnosticStage.EndpointParsing), dns], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.DnsNameNotFound);
        Assert.Equal(FindingSeverity.Error, findings[0].Severity);
    }

    [Fact]
    public void Analyze_TreatsASilentTcpTimeoutAsAPacketFilter()
    {
        StageResult dns = Ok(DiagnosticStage.DnsResolution, ("allAddressesPrivate", "False"));
        StageResult tcp = Failed(
            DiagnosticStage.TcpConnect,
            "The connection timed out.",
            ("socketError", "TimedOut"));

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [dns, tcp], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.TcpBlocked);
    }

    [Fact]
    public void Analyze_TreatsARefusalAsAHealthyPathWithNoListener()
    {
        StageResult tcp = Failed(
            DiagnosticStage.TcpConnect,
            "The connection was refused.",
            ("socketError", "ConnectionRefused"));

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [Ok(DiagnosticStage.DnsResolution), tcp], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.TcpRefused);
        Assert.DoesNotContain(findings, finding => finding.Code == FindingCodes.TcpBlocked);
    }

    [Fact]
    public void Analyze_AddsThePublicDnsButBlockedRuleForAzurePaasHosts()
    {
        StageResult dns = Ok(
            DiagnosticStage.DnsResolution,
            ("hostLooksLikeAzurePaas", "True"),
            ("allAddressesPrivate", "False"));
        StageResult tcp = Failed(
            DiagnosticStage.TcpConnect,
            "The connection timed out.",
            ("socketError", "TimedOut"));

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [dns, tcp], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.PublicDnsButBlocked);
    }

    [Fact]
    public void Analyze_ReportsTlsFailureOnlyWhenTcpSucceeded()
    {
        StageResult tcp = Ok(DiagnosticStage.TcpConnect);
        StageResult tls = Failed(DiagnosticStage.TlsHandshake, "The handshake failed.");

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [tcp, tls], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.TlsHandshakeFailed);
    }

    [Fact]
    public void Analyze_DetectsTlsInterceptionFromAnUntrustedRoot()
    {
        StageResult certificate = Failed(
            DiagnosticStage.CertificateValidation,
            "The certificate chain is not trusted.",
            ("chainStatus", "UntrustedRoot"),
            ("hostNameMatchesCertificate", "True"),
            ("isCurrentlyValid", "True"));

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [certificate], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.CertificateUntrustedRoot);
    }

    [Fact]
    public void Analyze_WarnsWhenTheCertificateExpiresSoon()
    {
        StageResult certificate = Ok(
            DiagnosticStage.CertificateValidation,
            ("daysUntilExpiry", (RootCauseAnalyzer.CertificateExpiryWarningDays - 1)
                .ToString(CultureInfo.InvariantCulture)));

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [certificate], []);

        Finding finding = Assert.Single(
            findings,
            candidate => candidate.Code == FindingCodes.CertificateExpiringSoon);
        Assert.Equal(FindingSeverity.Warning, finding.Severity);
    }

    [Fact]
    public void Analyze_TreatsA403AsReachableButRejected()
    {
        StageResult http = new()
        {
            Stage = DiagnosticStage.HttpRequest,
            Outcome = DiagnosticOutcome.Warning,
            Summary = "The server responded 403 Forbidden.",
            Evidence = new Dictionary<string, string>(StringComparer.Ordinal) { ["statusCode"] = "403" }
        };

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [http], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.Http403);
    }

    [Fact]
    public void Analyze_MapsSqlFirewallErrorNumbers()
    {
        StageResult sql = Failed(
            DiagnosticStage.SqlConnection,
            "Login failed.",
            ("sqlErrorNumber", "40615"));

        IReadOnlyList<Finding> findings = _analyzer.Analyze(SqlTarget(), [sql], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.SqlFirewall);
    }

    [Fact]
    public void Analyze_MapsServiceBusAuthorizationFailures()
    {
        StageResult serviceBus = Failed(
            DiagnosticStage.ServiceBusLink,
            "The link was refused.",
            ("failureReason", "Unauthorized"));

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [serviceBus], []);

        Assert.Contains(findings, finding => finding.Code == FindingCodes.ServiceBusUnauthorized);
    }

    [Fact]
    public void Analyze_ReportsNoIssueWhenNothingFailed()
    {
        IReadOnlyList<Finding> findings = _analyzer.Analyze(
            Target(),
            [Ok(DiagnosticStage.DnsResolution), Ok(DiagnosticStage.TcpConnect)],
            []);

        Finding finding = Assert.Single(findings);
        Assert.Equal(FindingCodes.NoIssueDetected, finding.Code);
        Assert.Equal(FindingSeverity.Information, finding.Severity);
    }

    [Fact]
    public void Analyze_OrdersFindingsMostSevereFirst()
    {
        StageResult dns = Ok(DiagnosticStage.DnsResolution, ("hostLooksLikeAzurePaas", "True"));
        StageResult tcp = Failed(
            DiagnosticStage.TcpConnect,
            "The connection timed out.",
            ("socketError", "TimedOut"));
        StageResult http = new()
        {
            Stage = DiagnosticStage.HttpRequest,
            Outcome = DiagnosticOutcome.Warning,
            Summary = "403",
            Evidence = new Dictionary<string, string>(StringComparer.Ordinal) { ["statusCode"] = "403" }
        };

        IReadOnlyList<Finding> findings = _analyzer.Analyze(Target(), [dns, tcp, http], []);

        Assert.Equal(FindingSeverity.Error, findings[0].Severity);
        Assert.Equal(FindingSeverity.Warning, findings[^1].Severity);
    }

    private static ProbeTarget Target()
    {
        return new ProbeTarget
        {
            RawValue = "example.com:443",
            Host = "example.com",
            Port = 443,
            ServiceKind = ServiceKind.GenericTcp,
            TlsOnConnect = true,
            HostIsIpLiteral = false
        };
    }

    private static ProbeTarget SqlTarget()
    {
        return new ProbeTarget
        {
            RawValue = "contoso.database.windows.net",
            Host = "contoso.database.windows.net",
            Port = 1433,
            ServiceKind = ServiceKind.AzureSql,
            TlsOnConnect = false,
            HostIsIpLiteral = false
        };
    }

    private static StageResult Ok(DiagnosticStage stage, params (string Key, string Value)[] evidence)
    {
        return new StageResult
        {
            Stage = stage,
            Outcome = DiagnosticOutcome.Succeeded,
            Summary = "The stage succeeded.",
            Evidence = ToEvidence(evidence)
        };
    }

    private static StageResult Failed(
        DiagnosticStage stage,
        string summary,
        params (string Key, string Value)[] evidence)
    {
        return new StageResult
        {
            Stage = stage,
            Outcome = DiagnosticOutcome.Failed,
            Summary = summary,
            Evidence = ToEvidence(evidence)
        };
    }

    private static Dictionary<string, string> ToEvidence((string Key, string Value)[] evidence)
    {
        var dictionary = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach ((string key, string value) in evidence)
        {
            dictionary[key] = value;
        }

        return dictionary;
    }
}
