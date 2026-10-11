using AzureConnectivityDoctor.Core.Analysis;
using AzureConnectivityDoctor.Core.Endpoints;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Probes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AzureConnectivityDoctor.IntegrationTests;

/// <summary>
/// Proves the end-to-end diagnostic probes against public internet failure modes (BadSSL, unroutable IPs, invalid domains).
/// </summary>
/// <remarks>
/// Opt-in through <c>ACD_INTEGRATION=1</c>. These tests require outbound internet access, but zero Azure infrastructure.
/// </remarks>
public sealed class PublicFailureModeIntegrationTests
{
    private static readonly RootCauseAnalyzer Analyzer = new();

    [Fact]
    public async Task DnsProbe_DetectsNonExistentDomain_EmitsDnsNotFoundFinding()
    {
        Assert.SkipUnless(IntegrationTestGate.IsEnabled, IntegrationTestGate.SkipReason);

        TargetParseResult parsed = new EndpointParser().Parse("https://this-domain-definitely-does-not-exist-acd-test-998877.org");
        Assert.True(parsed.Succeeded);
        ProbeTarget target = parsed.Target!;

        TimeSpan timeout = TimeSpan.FromSeconds(5);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        DnsProbeResult dns = await new DnsProbe(NullLogger<DnsProbe>.Instance)
            .ResolveAsync(target, timeout, cancellationToken);

        Assert.Equal(DiagnosticOutcome.Failed, dns.Result.Outcome);
        Assert.Empty(dns.Addresses);

        IReadOnlyList<Finding> findings = Analyzer.Analyze(target, [dns.Result], []);
        Assert.Contains(findings, f => f.Code == FindingCodes.DnsNameNotFound);
    }

    [Fact]
    public async Task TcpProbe_DetectsUnroutableBlackholeIp_EmitsTcpBlockedFinding()
    {
        Assert.SkipUnless(IntegrationTestGate.IsEnabled, IntegrationTestGate.SkipReason);

        // 192.0.2.1 is reserved for documentation (RFC 5737 TEST-NET-1) and silently drops packets.
        TargetParseResult parsed = new EndpointParser().Parse("192.0.2.1:443");
        Assert.True(parsed.Succeeded);
        ProbeTarget target = parsed.Target!;

        TimeSpan timeout = TimeSpan.FromSeconds(2);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        DnsProbeResult dns = await new DnsProbe(NullLogger<DnsProbe>.Instance)
            .ResolveAsync(target, timeout, cancellationToken);
        Assert.Equal(DiagnosticOutcome.Skipped, dns.Result.Outcome);

        TcpProbeResult tcp = await new TcpProbe(NullLogger<TcpProbe>.Instance)
            .ConnectAsync(target, dns.Addresses, timeout, cancellationToken);

        Assert.Equal(DiagnosticOutcome.Failed, tcp.Result.Outcome);
        Assert.Null(tcp.ConnectedAddress);

        IReadOnlyList<Finding> findings = Analyzer.Analyze(target, [dns.Result, tcp.Result], []);
        Assert.Contains(findings, f => f.Code == FindingCodes.TcpBlocked);
    }

    [Fact]
    public async Task TlsProbe_DetectsExpiredCertificate_EmitsCertExpiredFinding()
    {
        Assert.SkipUnless(IntegrationTestGate.IsEnabled, IntegrationTestGate.SkipReason);

        TargetParseResult parsed = new EndpointParser().Parse("https://expired.badssl.com");
        Assert.True(parsed.Succeeded);
        ProbeTarget target = parsed.Target!;

        TimeSpan timeout = TimeSpan.FromSeconds(10);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        DnsProbeResult dns = await new DnsProbe(NullLogger<DnsProbe>.Instance)
            .ResolveAsync(target, timeout, cancellationToken);
        Assert.Equal(DiagnosticOutcome.Succeeded, dns.Result.Outcome);

        TcpProbeResult tcp = await new TcpProbe(NullLogger<TcpProbe>.Instance)
            .ConnectAsync(target, dns.Addresses, timeout, cancellationToken);
        Assert.Equal(DiagnosticOutcome.Succeeded, tcp.Result.Outcome);

        TlsProbeResult tls = await new TlsProbe(NullLogger<TlsProbe>.Instance, TimeProvider.System)
            .HandshakeAsync(target, tcp.ConnectedAddress!, timeout, cancellationToken);

        Assert.Equal(DiagnosticOutcome.Succeeded, tls.Handshake.Outcome);
        Assert.Equal(DiagnosticOutcome.Failed, tls.Certificate.Outcome);

        IReadOnlyList<Finding> findings = Analyzer.Analyze(target, [dns.Result, tcp.Result, tls.Handshake, tls.Certificate], []);
        Assert.Contains(findings, f => f.Code == FindingCodes.CertificateExpired);
    }

    [Fact]
    public async Task TlsProbe_DetectsWrongHostName_EmitsCertNameMismatchFinding()
    {
        Assert.SkipUnless(IntegrationTestGate.IsEnabled, IntegrationTestGate.SkipReason);

        TargetParseResult parsed = new EndpointParser().Parse("https://wrong.host.badssl.com");
        Assert.True(parsed.Succeeded);
        ProbeTarget target = parsed.Target!;

        TimeSpan timeout = TimeSpan.FromSeconds(10);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        DnsProbeResult dns = await new DnsProbe(NullLogger<DnsProbe>.Instance)
            .ResolveAsync(target, timeout, cancellationToken);
        Assert.Equal(DiagnosticOutcome.Succeeded, dns.Result.Outcome);

        TcpProbeResult tcp = await new TcpProbe(NullLogger<TcpProbe>.Instance)
            .ConnectAsync(target, dns.Addresses, timeout, cancellationToken);
        Assert.Equal(DiagnosticOutcome.Succeeded, tcp.Result.Outcome);

        TlsProbeResult tls = await new TlsProbe(NullLogger<TlsProbe>.Instance, TimeProvider.System)
            .HandshakeAsync(target, tcp.ConnectedAddress!, timeout, cancellationToken);

        Assert.Equal(DiagnosticOutcome.Succeeded, tls.Handshake.Outcome);
        Assert.Equal(DiagnosticOutcome.Failed, tls.Certificate.Outcome);

        IReadOnlyList<Finding> findings = Analyzer.Analyze(target, [dns.Result, tcp.Result, tls.Handshake, tls.Certificate], []);
        Assert.Contains(findings, f => f.Code == FindingCodes.CertificateNameMismatch);
    }

    [Fact]
    public async Task TlsProbe_DetectsSelfSignedCert_EmitsUntrustedRootFinding()
    {
        Assert.SkipUnless(IntegrationTestGate.IsEnabled, IntegrationTestGate.SkipReason);

        TargetParseResult parsed = new EndpointParser().Parse("https://self-signed.badssl.com");
        Assert.True(parsed.Succeeded);
        ProbeTarget target = parsed.Target!;

        TimeSpan timeout = TimeSpan.FromSeconds(10);
        CancellationToken cancellationToken = TestContext.Current.CancellationToken;

        DnsProbeResult dns = await new DnsProbe(NullLogger<DnsProbe>.Instance)
            .ResolveAsync(target, timeout, cancellationToken);
        Assert.Equal(DiagnosticOutcome.Succeeded, dns.Result.Outcome);

        TcpProbeResult tcp = await new TcpProbe(NullLogger<TcpProbe>.Instance)
            .ConnectAsync(target, dns.Addresses, timeout, cancellationToken);
        Assert.Equal(DiagnosticOutcome.Succeeded, tcp.Result.Outcome);

        TlsProbeResult tls = await new TlsProbe(NullLogger<TlsProbe>.Instance, TimeProvider.System)
            .HandshakeAsync(target, tcp.ConnectedAddress!, timeout, cancellationToken);

        Assert.Equal(DiagnosticOutcome.Succeeded, tls.Handshake.Outcome);
        Assert.Equal(DiagnosticOutcome.Failed, tls.Certificate.Outcome);

        IReadOnlyList<Finding> findings = Analyzer.Analyze(target, [dns.Result, tcp.Result, tls.Handshake, tls.Certificate], []);
        Assert.Contains(findings, f => f.Code == FindingCodes.CertificateUntrustedRoot);
    }
}
