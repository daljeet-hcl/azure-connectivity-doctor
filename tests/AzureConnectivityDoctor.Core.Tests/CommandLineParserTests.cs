using AzureConnectivityDoctor.Cli;
using AzureConnectivityDoctor.Core.Options;
using Xunit;

namespace AzureConnectivityDoctor.Core.Tests;

/// <summary>Covers the hand-written command-line parser.</summary>
public sealed class CommandLineParserTests
{
    [Fact]
    public void Parse_WithNoArgumentsShowsHelp()
    {
        CommandLineParseResult result = CommandLineParser.Parse([]);

        Assert.True(result.ShowHelp);
    }

    [Theory]
    [InlineData("-h")]
    [InlineData("--help")]
    public void Parse_RecognisesHelp(string flag)
    {
        Assert.True(CommandLineParser.Parse([flag]).ShowHelp);
    }

    [Fact]
    public void Parse_RecognisesVersion()
    {
        Assert.True(CommandLineParser.Parse(["--version"]).ShowVersion);
    }

    [Fact]
    public void Parse_AcceptsBareEndpointsAndFlags()
    {
        CommandLineParseResult result = CommandLineParser.Parse(
            ["https://example.com", "--http", "--identity", "--concurrency", "8", "--timeout", "20"]);

        Assert.True(result.Succeeded, result.Error);
        DoctorOptions options = result.Options!;
        Assert.Equal(["https://example.com"], options.Endpoints);
        Assert.True(options.EnableHttp);
        Assert.True(options.EnableIdentity);
        Assert.Equal(8, options.MaxConcurrency);
        Assert.Equal(TimeSpan.FromSeconds(20), options.Timeout);
    }

    [Fact]
    public void Parse_SupportsRepeatedEndpointOptions()
    {
        CommandLineParseResult result = CommandLineParser.Parse(
            ["--endpoint", "a.example.com:443", "--endpoint", "b.example.com:443"]);

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal(2, result.Options!.Endpoints.Count);
    }

    [Fact]
    public void Parse_DisablesReportsOnRequest()
    {
        CommandLineParseResult result = CommandLineParser.Parse(
            ["example.com:443", "--no-json", "--no-markdown", "--quiet"]);

        Assert.True(result.Succeeded, result.Error);
        Assert.Null(result.Options!.JsonOutputPath);
        Assert.Null(result.Options.MarkdownOutputPath);
        Assert.False(result.Options.PrintToConsole);
    }

    [Fact]
    public void Parse_RejectsUnknownOptions()
    {
        CommandLineParseResult result = CommandLineParser.Parse(["--nope"]);

        Assert.False(result.Succeeded);
        Assert.Contains("Unknown option", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsAnOptionWithoutItsValue()
    {
        CommandLineParseResult result = CommandLineParser.Parse(["--endpoint"]);

        Assert.False(result.Succeeded);
        Assert.Contains("requires a value", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RejectsAnOutOfRangeConcurrency()
    {
        CommandLineParseResult result = CommandLineParser.Parse(["example.com:443", "--concurrency", "0"]);

        Assert.False(result.Succeeded);
        Assert.Contains("--concurrency", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RequiresAtLeastOneEndpoint()
    {
        CommandLineParseResult result = CommandLineParser.Parse(["--http"]);

        Assert.False(result.Succeeded);
        Assert.Contains("No endpoint was supplied", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_RequiresAResourceIdWithTheAzureAssessment()
    {
        CommandLineParseResult result = CommandLineParser.Parse(["example.com:443", "--azure-assessment"]);

        Assert.False(result.Succeeded);
        Assert.Contains("--resource-id", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void Parse_AcceptsAZeroOverallTimeoutMeaningNoLimit()
    {
        CommandLineParseResult result = CommandLineParser.Parse(
            ["example.com:443", "--overall-timeout", "0"]);

        Assert.True(result.Succeeded, result.Error);
        Assert.Equal(TimeSpan.Zero, result.Options!.OverallTimeout);
    }
}
