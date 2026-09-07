using System.Diagnostics;
using System.Globalization;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>
/// Opens a real Azure SQL connection and runs <c>SELECT 1</c>.
/// </summary>
/// <remarks>
/// <para>
/// A TCP connection to port 1433 proves almost nothing about Azure SQL. The gateway accepts
/// the connection first and only then applies the firewall, the virtual network rules and the
/// private-endpoint policy, so the request can still be rejected after a perfectly healthy
/// TCP handshake. The only reliable test is to complete the TDS login.
/// </para>
/// <para>
/// Authentication uses <see cref="SqlConnection.AccessToken"/> populated from the tool's own
/// <c>TokenCredential</c>. This keeps the credential chain identical to every other probe and
/// avoids adding an authentication provider package. When a token is set, the connection
/// string must not contain <c>User ID</c>, <c>Password</c> or <c>Integrated Security</c>;
/// the builder below never adds them.
/// </para>
/// <para>
/// The connection is opened with <c>Encrypt=Mandatory</c> and <c>TrustServerCertificate=false</c>,
/// so a successful open is itself proof that TLS was negotiated inside TDS and that the
/// gateway certificate chained to a trusted root.
/// </para>
/// </remarks>
public sealed class SqlProbe : ISqlProbe
{
    private const string ApplicationName = "AzureConnectivityDoctor";

    private readonly ILogger<SqlProbe> _logger;

    /// <summary>Creates the probe.</summary>
    /// <param name="logger">The logger used for progress output.</param>
    public SqlProbe(ILogger<SqlProbe> logger)
    {
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<StageResult> ProbeAsync(
        ProbeTarget target,
        string? accessToken,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (target.ServiceKind != ServiceKind.AzureSql)
        {
            return StageResult.Skipped(
                DiagnosticStage.SqlConnection,
                "The endpoint is not an Azure SQL server.");
        }

        if (accessToken is null)
        {
            return StageResult.NotAttempted(
                DiagnosticStage.SqlConnection,
                "No Microsoft Entra ID access token was available, so the SQL login was not attempted. " +
                "Run with identity probing enabled and a credential that can obtain a token for the " +
                "Azure SQL scope.");
        }

        int timeoutSeconds = Math.Max(1, (int)Math.Ceiling(timeout.TotalSeconds));
        string database = string.IsNullOrWhiteSpace(target.DatabaseName) ? "master" : target.DatabaseName;

        var builder = new SqlConnectionStringBuilder
        {
            DataSource = string.Create(CultureInfo.InvariantCulture, $"tcp:{target.Host},{target.Port}"),
            InitialCatalog = database,
            Encrypt = SqlConnectionEncryptOption.Mandatory,
            TrustServerCertificate = false,
            ConnectTimeout = timeoutSeconds,
            ApplicationName = ApplicationName,
            Pooling = false,
            MultipleActiveResultSets = false
        };

        _logger.LogInformation(
            "Opening an Azure SQL connection to {Host} database {Database}",
            target.Host,
            database);

        long start = Stopwatch.GetTimestamp();

        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["dataSource"] = builder.DataSource,
            ["database"] = database,
            ["encrypt"] = "Mandatory",
            ["trustServerCertificate"] = "false",
            ["authentication"] = "Microsoft Entra ID access token",
            ["connectTimeoutSeconds"] = timeoutSeconds.ToString(CultureInfo.InvariantCulture)
        };

        try
        {
            await using var connection = new SqlConnection(builder.ConnectionString)
            {
                AccessToken = accessToken
            };

            await connection.OpenAsync(cancellationToken);

            await using var command = new SqlCommand("SELECT 1;", connection)
            {
                CommandTimeout = timeoutSeconds
            };

            object? scalar = await command.ExecuteScalarAsync(cancellationToken);
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            evidence["serverVersion"] = connection.ServerVersion;
            evidence["clientConnectionId"] = connection.ClientConnectionId.ToString();
            evidence["queryResult"] = Convert.ToString(scalar, CultureInfo.InvariantCulture) ?? "(null)";
            evidence["totalMilliseconds"] = elapsed.ToString("F1", CultureInfo.InvariantCulture);

            return new StageResult
            {
                Stage = DiagnosticStage.SqlConnection,
                Outcome = DiagnosticOutcome.Succeeded,
                Summary =
                    $"Connected to '{database}' on {target.Host} and executed a read-only query in " +
                    $"{elapsed:F0} ms. Because encryption was mandatory and the server certificate was " +
                    "not trusted blindly, the network path, TLS and authorisation are all confirmed.",
                DurationMilliseconds = elapsed,
                Evidence = evidence
            };
        }
        catch (SqlException exception)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            evidence["sqlErrorNumber"] = exception.Number.ToString(CultureInfo.InvariantCulture);
            evidence["sqlErrorClass"] = exception.Class.ToString(CultureInfo.InvariantCulture);
            evidence["sqlErrorState"] = exception.State.ToString(CultureInfo.InvariantCulture);
            evidence["clientConnectionId"] = exception.ClientConnectionId.ToString();
            evidence["interpretation"] = Interpret(exception.Number);

            return new StageResult
            {
                Stage = DiagnosticStage.SqlConnection,
                Outcome = DiagnosticOutcome.Failed,
                Summary =
                    $"The Azure SQL login to '{database}' on {target.Host} failed with error " +
                    $"{exception.Number}. {Interpret(exception.Number)}",
                DurationMilliseconds = elapsed,
                ErrorType = nameof(SqlException),
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            };
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            return new StageResult
            {
                Stage = DiagnosticStage.SqlConnection,
                Outcome = DiagnosticOutcome.Failed,
                Summary = $"The Azure SQL connection to {target.Host} failed before a server error was returned.",
                DurationMilliseconds = elapsed,
                ErrorType = exception.GetType().Name,
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            };
        }
    }

    /// <summary>
    /// Translates the Azure SQL error numbers that carry connectivity meaning.
    /// </summary>
    /// <param name="errorNumber">The value of <see cref="SqlException.Number"/>.</param>
    /// <returns>A plain-language interpretation.</returns>
    /// <remarks>
    /// Only errors whose meaning is documented and stable are translated. Anything else is
    /// reported verbatim rather than guessed at.
    /// </remarks>
    internal static string Interpret(int errorNumber)
    {
        return errorNumber switch
        {
            -2 or 10060 or 11001 =>
                "The connection timed out before the server replied. This is the signature of a blocked " +
                "network path rather than a rejected login.",
            18456 =>
                "The login was rejected. The network path works. Create a contained database user for the " +
                "identity and grant it the required role.",
            40615 =>
                "The server firewall rejected the client IP address. Add a firewall rule, or allow Azure " +
                "services, or connect through a private endpoint.",
            40914 =>
                "A virtual network rule rejected the connection. The source subnet is not permitted by the " +
                "server's virtual network rules.",
            4060 or 40532 =>
                "The server was reached and the login was accepted, but the requested database could not be " +
                "opened. Check the database name and the identity's permissions on it.",
            233 or 64 =>
                "The connection was established and then closed by the server before login completed. This " +
                "often indicates a TLS or proxy problem in the path.",
            40613 =>
                "The database is currently unavailable. Retry, then check the service health of the server.",
            _ =>
                "See the accompanying error message for the server-reported detail."
        };
    }
}
