using System.Diagnostics;
using System.Globalization;
using System.Net;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Extensions.Logging;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>
/// Sends a single, side-effect-free HTTP request and records the response.
/// </summary>
/// <remarks>
/// <para>
/// The probe sends <c>HEAD</c> first because it is the only HTTP method guaranteed to have no
/// side effects and no response body. Some servers and API gateways reject <c>HEAD</c> with
/// 405 or 501; in that case a single <c>GET</c> is issued and the body is discarded without
/// being buffered.
/// </para>
/// <para>
/// Response headers are recorded selectively. Capturing every header would routinely place
/// <c>Set-Cookie</c> and <c>Authorization</c> echoes into a report that operators paste into
/// tickets.
/// </para>
/// </remarks>
public sealed class HttpProbe : IHttpProbe
{
    /// <summary>The name of the <see cref="HttpClient"/> registered for probing.</summary>
    public const string HttpClientName = "connectivity-probe";

    private static readonly string[] InterestingHeaders =
    [
        "Server",
        "Date",
        "Content-Type",
        "Content-Length",
        "X-Powered-By",
        "X-AspNet-Version",
        "X-Azure-Ref",
        "X-Cache",
        "X-MSEdge-Ref",
        "Strict-Transport-Security",
        "Retry-After"
    ];

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<HttpProbe> _logger;

    /// <summary>Creates the probe.</summary>
    /// <param name="httpClientFactory">Supplies pooled, correctly configured clients.</param>
    /// <param name="logger">The logger used for progress output.</param>
    public HttpProbe(IHttpClientFactory httpClientFactory, ILogger<HttpProbe> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<StageResult> SendAsync(
        ProbeTarget target,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (target.HttpUri is null)
        {
            return StageResult.Skipped(
                DiagnosticStage.HttpRequest,
                "The endpoint is not an HTTP or HTTPS URL.");
        }

        _logger.LogInformation("Sending HTTP request to {Uri}", target.HttpUri);

        HttpClient client = _httpClientFactory.CreateClient(HttpClientName);
        long start = Stopwatch.GetTimestamp();

        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        try
        {
            using HttpResponseMessage response =
                await SendWithHeadThenGetAsync(client, target.HttpUri, timeoutSource.Token);
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["requestUri"] = target.HttpUri.ToString(),
                ["requestMethod"] = response.RequestMessage?.Method.Method ?? "UNKNOWN",
                ["statusCode"] = ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture),
                ["statusDescription"] = response.StatusCode.ToString(),
                ["httpVersion"] = response.Version.ToString(),
                ["responseMilliseconds"] = elapsed.ToString("F1", CultureInfo.InvariantCulture)
            };

            foreach (string headerName in InterestingHeaders)
            {
                if (response.Headers.TryGetValues(headerName, out IEnumerable<string>? values))
                {
                    evidence["header." + headerName] = string.Join(", ", values);
                }
                else if (response.Content.Headers.TryGetValues(headerName, out IEnumerable<string>? contentValues))
                {
                    evidence["header." + headerName] = string.Join(", ", contentValues);
                }
            }

            AddProxyEvidence(evidence);

            // Any HTTP status proves end-to-end reachability. Only certain statuses point at a
            // network-level policy problem rather than an application problem.
            DiagnosticOutcome outcome = response.StatusCode switch
            {
                HttpStatusCode.Forbidden => DiagnosticOutcome.Warning,
                HttpStatusCode.ProxyAuthenticationRequired => DiagnosticOutcome.Warning,
                HttpStatusCode.RequestTimeout => DiagnosticOutcome.Warning,
                HttpStatusCode.BadGateway => DiagnosticOutcome.Warning,
                HttpStatusCode.ServiceUnavailable => DiagnosticOutcome.Warning,
                HttpStatusCode.GatewayTimeout => DiagnosticOutcome.Warning,
                _ => DiagnosticOutcome.Succeeded
            };

            return new StageResult
            {
                Stage = DiagnosticStage.HttpRequest,
                Outcome = outcome,
                Summary =
                    $"The server responded {(int)response.StatusCode} {response.StatusCode} in {elapsed:F0} ms. " +
                    "A response of any status confirms end-to-end HTTP reachability.",
                DurationMilliseconds = elapsed,
                Evidence = evidence
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["requestUri"] = target.HttpUri.ToString(),
                ["timeoutSeconds"] = timeout.TotalSeconds.ToString("F0", CultureInfo.InvariantCulture)
            };
            AddProxyEvidence(evidence);

            return new StageResult
            {
                Stage = DiagnosticStage.HttpRequest,
                Outcome = DiagnosticOutcome.Failed,
                Summary = $"No HTTP response was received within {timeout.TotalSeconds:F0} s.",
                DurationMilliseconds = elapsed,
                ErrorType = nameof(TimeoutException),
                Evidence = evidence
            };
        }
        catch (HttpRequestException exception)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["requestUri"] = target.HttpUri.ToString(),
                ["httpRequestError"] = exception.HttpRequestError.ToString()
            };

            if (exception.StatusCode is not null)
            {
                evidence["statusCode"] = ((int)exception.StatusCode.Value).ToString(CultureInfo.InvariantCulture);
            }

            AddProxyEvidence(evidence);

            return new StageResult
            {
                Stage = DiagnosticStage.HttpRequest,
                Outcome = DiagnosticOutcome.Failed,
                Summary = $"The HTTP request to {target.HttpUri} failed ({exception.HttpRequestError}).",
                DurationMilliseconds = elapsed,
                ErrorType = nameof(HttpRequestException),
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            };
        }
    }

    private static async Task<HttpResponseMessage> SendWithHeadThenGetAsync(
        HttpClient client,
        Uri uri,
        CancellationToken cancellationToken)
    {
        using var headRequest = new HttpRequestMessage(HttpMethod.Head, uri);
        HttpResponseMessage response = await client.SendAsync(
            headRequest,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);

        if (response.StatusCode is not (HttpStatusCode.MethodNotAllowed or HttpStatusCode.NotImplemented))
        {
            return response;
        }

        response.Dispose();

        using var getRequest = new HttpRequestMessage(HttpMethod.Get, uri);
        return await client.SendAsync(
            getRequest,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
    }

    /// <summary>
    /// Records whether the process has an HTTP proxy configured.
    /// </summary>
    /// <remarks>
    /// An unexpected proxy is a common and easily missed cause of TLS interception and of
    /// 407 responses inside corporate networks and locked-down build agents. Proxy URLs may
    /// embed credentials, so the values are redacted.
    /// </remarks>
    private static void AddProxyEvidence(Dictionary<string, string> evidence)
    {
        foreach (string variable in new[] { "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY" })
        {
            string? value = Environment.GetEnvironmentVariable(variable)
                ?? Environment.GetEnvironmentVariable(variable.ToLowerInvariant());

            if (!string.IsNullOrEmpty(value))
            {
                evidence["proxy." + variable] = SecretRedactor.Redact(value) ?? string.Empty;
            }
        }
    }
}
