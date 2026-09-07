using AzureConnectivityDoctor.Core.Endpoints;
using AzureConnectivityDoctor.Core.Model;
using Xunit;

namespace AzureConnectivityDoctor.Core.Tests;

/// <summary>Covers the accepted endpoint forms and the deliberate rejections.</summary>
public sealed class EndpointParserTests
{
    private readonly EndpointParser _parser = new();

    [Theory]
    [InlineData("https://example.com", "example.com", 443, ServiceKind.Http, true)]
    [InlineData("http://example.com", "example.com", 80, ServiceKind.Http, false)]
    [InlineData("https://example.com:8443/health", "example.com", 8443, ServiceKind.Http, true)]
    [InlineData("example.com:5432", "example.com", 5432, ServiceKind.GenericTcp, false)]
    [InlineData("contoso.database.windows.net", "contoso.database.windows.net", 1433, ServiceKind.AzureSql, false)]
    [InlineData("contoso.servicebus.windows.net", "contoso.servicebus.windows.net", 5671, ServiceKind.AzureServiceBus, true)]
    public void Parse_AcceptsSupportedForms(
        string input,
        string expectedHost,
        int expectedPort,
        ServiceKind expectedKind,
        bool expectedTlsOnConnect)
    {
        TargetParseResult result = _parser.Parse(input);

        Assert.True(result.Succeeded, result.Error);
        Assert.NotNull(result.Target);
        Assert.Equal(expectedHost, result.Target!.Host);
        Assert.Equal(expectedPort, result.Target.Port);
        Assert.Equal(expectedKind, result.Target.ServiceKind);
        Assert.Equal(expectedTlsOnConnect, result.Target.TlsOnConnect);
    }

    [Fact]
    public void Parse_ReadsIPv6LiteralWithPort()
    {
        TargetParseResult result = _parser.Parse("[2603:1010::1]:443");

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("2603:1010::1", result.Target!.Host);
        Assert.Equal(443, result.Target.Port);
        Assert.True(result.Target.HostIsIpLiteral);
    }

    [Fact]
    public void Parse_RejectsCredentialsInTheEndpoint()
    {
        TargetParseResult result = _parser.Parse("https://user:secret@example.com");

        Assert.False(result.Succeeded);
        Assert.Contains("Credentials must never be passed", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsAHostWithNoInferablePort()
    {
        TargetParseResult result = _parser.Parse("internal-db");

        Assert.False(result.Succeeded);
        Assert.Contains("host:port", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsAnOutOfRangePort()
    {
        TargetParseResult result = _parser.Parse("example.com:70000");

        Assert.False(result.Succeeded);
        Assert.Contains("1-65535", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsEmptyInput()
    {
        TargetParseResult result = _parser.Parse("   ");

        Assert.False(result.Succeeded);
        Assert.Equal("The endpoint is empty.", result.Error);
    }

    [Fact]
    public void Parse_NeverEnablesTlsOnConnectForAzureSql()
    {
        // TDS upgrades to TLS during PRELOGIN, so a direct handshake at 1433 would be misleading.
        TargetParseResult result = _parser.Parse("contoso.database.windows.net:1433");

        Assert.True(result.Succeeded, result.Error);
        Assert.False(result.Target!.TlsOnConnect);
    }

    [Fact]
    public void Parse_CapturesTheServiceBusEntityFromThePath()
    {
        TargetParseResult result = _parser.Parse("sb://contoso.servicebus.windows.net/orders");

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("orders", result.Target!.EntityName);
    }

    [Fact]
    public void Parse_CapturesTheSqlDatabaseFromThePath()
    {
        TargetParseResult result = _parser.Parse("contoso.database.windows.net/inventory");

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal("inventory", result.Target!.DatabaseName);
    }
}
