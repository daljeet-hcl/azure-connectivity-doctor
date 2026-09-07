using AzureConnectivityDoctor.Core.Security;
using Xunit;

namespace AzureConnectivityDoctor.Core.Tests;

/// <summary>Covers the redaction patterns applied to every reported value.</summary>
public sealed class SecretRedactorTests
{
    [Theory]
    [InlineData("Server=x;Password=hunter2;")]
    [InlineData("Endpoint=sb://x/;SharedAccessKey=abc123def456")]
    [InlineData("AccountKey=Zm9vYmFyYmF6")]
    [InlineData("client_secret=aVeryLongSecretValue")]
    public void Redact_RemovesKeyValueSecrets(string input)
    {
        string redacted = SecretRedactor.Redact(input)!;

        Assert.Contains(SecretRedactor.Placeholder, redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("abc123def456", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("Zm9vYmFyYmF6", redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("aVeryLongSecretValue", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_RemovesBearerTokens()
    {
        string redacted = SecretRedactor.Redact("Authorization: Bearer abcdefghijklmnop")!;

        Assert.DoesNotContain("abcdefghijklmnop", redacted, StringComparison.Ordinal);
        Assert.Contains(SecretRedactor.Placeholder, redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_RemovesSharedAccessSignatures()
    {
        string redacted = SecretRedactor.Redact("https://x/?sv=2021&sig=Zm9vYmFyYmF6cXV4")!;

        Assert.DoesNotContain("Zm9vYmFyYmF6cXV4", redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Redact_RemovesBareJsonWebTokens()
    {
        const string Jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g";

        string redacted = SecretRedactor.Redact("token " + Jwt)!;

        Assert.Equal("token " + SecretRedactor.Placeholder, redacted);
    }

    [Fact]
    public void Redact_LeavesHarmlessTextAlone()
    {
        const string Input = "Connection to contoso.database.windows.net:1433 timed out after 10 s.";

        Assert.Equal(Input, SecretRedactor.Redact(Input));
    }

    [Fact]
    public void Redact_PassesNullThrough()
    {
        Assert.Null(SecretRedactor.Redact(null));
    }

    [Fact]
    public void RedactEvidence_KeepsKeysAndRedactsValues()
    {
        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["host"] = "contoso.database.windows.net",
            ["connectionString"] = "Server=x;Password=hunter2;"
        };

        IReadOnlyDictionary<string, string> redacted = SecretRedactor.RedactEvidence(evidence);

        Assert.Equal("contoso.database.windows.net", redacted["host"]);
        Assert.DoesNotContain("hunter2", redacted["connectionString"], StringComparison.Ordinal);
    }
}
