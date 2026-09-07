using System.Net;
using System.Net.Sockets;
using AzureConnectivityDoctor.Core.Endpoints;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Probes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AzureConnectivityDoctor.IntegrationTests;

/// <summary>
/// Exercises the real TCP probe against a listener started inside the test process.
/// </summary>
/// <remarks>
/// These tests use the loopback interface only, so they need no outbound connectivity, no Azure
/// subscription and no credentials. They run on every build, unlike the tests gated by
/// <see cref="IntegrationTestGate"/>.
/// </remarks>
public sealed class LoopbackConnectivityTests
{
    [Fact]
    public async Task TcpProbe_ConnectsToAListeningPort()
    {
        using var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        listener.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        listener.Listen(1);

        int port = ((IPEndPoint)listener.LocalEndPoint!).Port;
        ProbeTarget target = ParseLoopback(port);

        var probe = new TcpProbe(NullLogger<TcpProbe>.Instance);
        TcpProbeResult result = await probe.ConnectAsync(
            target,
            [IPAddress.Loopback],
            TimeSpan.FromSeconds(5),
            TestContext.Current.CancellationToken);

        Assert.Equal(DiagnosticOutcome.Succeeded, result.Result.Outcome);
        Assert.Equal(IPAddress.Loopback, result.ConnectedAddress);
    }

    [Fact]
    public async Task TcpProbe_ReportsARefusalWhenNothingIsListening()
    {
        // Bind and immediately close, so the port is almost certainly free and will answer with a
        // reset rather than dropping the packet. A refusal is the evidence this test is about.
        int port;

        using (var probeSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp))
        {
            probeSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            port = ((IPEndPoint)probeSocket.LocalEndPoint!).Port;
        }

        ProbeTarget target = ParseLoopback(port);

        var probe = new TcpProbe(NullLogger<TcpProbe>.Instance);
        TcpProbeResult result = await probe.ConnectAsync(
            target,
            [IPAddress.Loopback],
            TimeSpan.FromSeconds(5),
            TestContext.Current.CancellationToken);

        Assert.Equal(DiagnosticOutcome.Failed, result.Result.Outcome);
        Assert.Null(result.ConnectedAddress);
    }

    [Fact]
    public async Task DnsProbe_ResolvesLocalhost()
    {
        ProbeTarget target = ParseLoopback(443);

        var probe = new DnsProbe(NullLogger<DnsProbe>.Instance);
        DnsProbeResult result = await probe.ResolveAsync(
            target with { Host = "localhost" },
            TimeSpan.FromSeconds(5),
            TestContext.Current.CancellationToken);

        Assert.Equal(DiagnosticOutcome.Succeeded, result.Result.Outcome);
        Assert.NotEmpty(result.Addresses);
    }

    private static ProbeTarget ParseLoopback(int port)
    {
        TargetParseResult parsed = new EndpointParser().Parse($"127.0.0.1:{port}");
        Assert.True(parsed.Succeeded, parsed.Error);
        return parsed.Target!;
    }
}
