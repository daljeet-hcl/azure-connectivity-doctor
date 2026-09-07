using AzureConnectivityDoctor.Core.Endpoints;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Probes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AzureConnectivityDoctor.IntegrationTests;

/// <summary>
/// Exercises the DNS, TCP and TLS probes against a real public endpoint.
/// </summary>
/// <remarks>
/// Opt-in through <c>ACD_INTEGRATION=1</c> because the result depends on the environment's
/// outbound connectivity rather than on the code under test.
/// </remarks>
public sealed class PublicEndpointTests
{
    private const string PublicHost = "https://learn.microsoft.com";

    [Fact]
    public async Task DnsTcpAndTls_SucceedAgainstAPublicHttpsEndpoint()
    {
        Assert.SkipUnless(IntegrationTestGate.IsEnabled, IntegrationTestGate.SkipReason);

        TargetParseResult parsed = new EndpointParser().Parse(PublicHost);
        Assert.True(parsed.Succeeded, parsed.Error);
        ProbeTarget target = parsed.Target!;

        TimeSpan timeout = TimeSpan.FromSeconds(15);
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
        Assert.Equal(DiagnosticOutcome.Succeeded, tls.Certificate.Outcome);
    }
}
