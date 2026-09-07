namespace AzureConnectivityDoctor.IntegrationTests;

/// <summary>
/// Decides whether environment-dependent tests may run.
/// </summary>
/// <remarks>
/// These tests touch the real network. They are opt-in so that a clean clone on an air-gapped
/// machine, or a fork's pull-request build, still produces a green run instead of failures that
/// say nothing about the code. Set <c>ACD_INTEGRATION=1</c> to enable them.
/// </remarks>
internal static class IntegrationTestGate
{
    /// <summary>The environment variable that enables the network-dependent tests.</summary>
    internal const string EnableVariable = "ACD_INTEGRATION";

    /// <summary>The reason reported when the tests are skipped.</summary>
    internal const string SkipReason =
        "Set ACD_INTEGRATION=1 to run the network-dependent integration tests.";

    /// <summary>Whether the network-dependent tests are enabled.</summary>
    internal static bool IsEnabled =>
        string.Equals(
            Environment.GetEnvironmentVariable(EnableVariable),
            "1",
            StringComparison.Ordinal);
}
