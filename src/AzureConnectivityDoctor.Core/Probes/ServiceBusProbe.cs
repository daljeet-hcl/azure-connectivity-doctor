using System.Diagnostics;
using System.Globalization;
using Azure.Core;
using Azure.Messaging.ServiceBus;
using AzureConnectivityDoctor.Core.Identity;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Extensions.Logging;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>
/// Proves that an Azure Service Bus entity is reachable and authorised, without sending a message.
/// </summary>
/// <remarks>
/// <para>
/// The probe creates a sender and then calls <c>CreateMessageBatchAsync</c>. That call is the
/// smallest operation that forces the client to open the AMQP connection, open the link to the
/// named entity and present its token, because the service must return the negotiated maximum
/// batch size. Nothing is ever sent and no message is ever enqueued, so the probe is safe to
/// run against a production namespace.
/// </para>
/// <para>
/// Retries are disabled. A diagnostic tool must report the first failure exactly as it
/// occurred; silently retrying would hide an intermittent fault and inflate the reported
/// duration.
/// </para>
/// </remarks>
public sealed class ServiceBusProbe : IServiceBusProbe
{
    private readonly ICredentialProvider _credentialProvider;
    private readonly ILogger<ServiceBusProbe> _logger;

    /// <summary>Creates the probe.</summary>
    /// <param name="credentialProvider">Supplies the shared credential.</param>
    /// <param name="logger">The logger used for progress output.</param>
    public ServiceBusProbe(ICredentialProvider credentialProvider, ILogger<ServiceBusProbe> logger)
    {
        _credentialProvider = credentialProvider;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<StageResult> ProbeAsync(
        ProbeTarget target,
        bool useWebSockets,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);

        if (target.ServiceKind != ServiceKind.AzureServiceBus)
        {
            return StageResult.Skipped(
                DiagnosticStage.ServiceBusLink,
                "The endpoint is not an Azure Service Bus namespace.");
        }

        if (string.IsNullOrWhiteSpace(target.EntityName))
        {
            return StageResult.Skipped(
                DiagnosticStage.ServiceBusLink,
                "No queue or topic name was supplied. Append the entity name to the endpoint, for example " +
                "'my-namespace.servicebus.windows.net/my-queue', to test the AMQP link and authorisation.");
        }

        ServiceBusTransportType transport = useWebSockets
            ? ServiceBusTransportType.AmqpWebSockets
            : ServiceBusTransportType.AmqpTcp;

        var clientOptions = new ServiceBusClientOptions
        {
            TransportType = transport,
            RetryOptions = new ServiceBusRetryOptions
            {
                Mode = ServiceBusRetryMode.Fixed,
                MaxRetries = 0,
                TryTimeout = timeout,
                Delay = TimeSpan.FromMilliseconds(100),
                MaxDelay = TimeSpan.FromSeconds(1)
            }
        };

        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["fullyQualifiedNamespace"] = target.Host,
            ["entityName"] = target.EntityName,
            ["transportType"] = transport.ToString(),
            ["transportPort"] = useWebSockets ? "443" : "5671",
            ["tokenScope"] = AzureScopes.ForServiceBus(target.Host),
            ["operation"] = "CreateMessageBatchAsync (no message is sent)"
        };

        _logger.LogInformation(
            "Opening a Service Bus link to {Entity} on {Namespace} using {Transport}",
            target.EntityName,
            target.Host,
            transport);

        TokenCredential credential = _credentialProvider.GetCredential();
        long start = Stopwatch.GetTimestamp();

        try
        {
            await using var client = new ServiceBusClient(target.Host, credential, clientOptions);
            ServiceBusSender sender = client.CreateSender(target.EntityName);

            using ServiceBusMessageBatch batch = await sender.CreateMessageBatchAsync(cancellationToken);
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            evidence["maxBatchSizeBytes"] = batch.MaxSizeInBytes.ToString(CultureInfo.InvariantCulture);
            evidence["totalMilliseconds"] = elapsed.ToString("F1", CultureInfo.InvariantCulture);

            return new StageResult
            {
                Stage = DiagnosticStage.ServiceBusLink,
                Outcome = DiagnosticOutcome.Succeeded,
                Summary =
                    $"An AMQP link to '{target.EntityName}' on {target.Host} was established in " +
                    $"{elapsed:F0} ms. The network path, TLS and the identity's send authorisation are all " +
                    "confirmed. No message was sent.",
                DurationMilliseconds = elapsed,
                Evidence = evidence
            };
        }
        catch (ServiceBusException exception)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            evidence["failureReason"] = exception.Reason.ToString();
            evidence["isTransient"] = exception.IsTransient.ToString(CultureInfo.InvariantCulture);
            evidence["interpretation"] = Interpret(exception.Reason);

            return new StageResult
            {
                Stage = DiagnosticStage.ServiceBusLink,
                Outcome = DiagnosticOutcome.Failed,
                Summary =
                    $"The AMQP link to '{target.EntityName}' on {target.Host} failed " +
                    $"({exception.Reason}). {Interpret(exception.Reason)}",
                DurationMilliseconds = elapsed,
                ErrorType = nameof(ServiceBusException),
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            };
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            return new StageResult
            {
                Stage = DiagnosticStage.ServiceBusLink,
                Outcome = DiagnosticOutcome.Failed,
                Summary = $"The Service Bus client could not reach {target.Host}.",
                DurationMilliseconds = elapsed,
                ErrorType = exception.GetType().Name,
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            };
        }
    }

    /// <summary>Translates the documented Service Bus failure reasons into operator guidance.</summary>
    /// <param name="reason">The reported failure reason.</param>
    /// <returns>A plain-language interpretation.</returns>
    internal static string Interpret(ServiceBusFailureReason reason)
    {
        return reason switch
        {
            ServiceBusFailureReason.MessagingEntityNotFound =>
                "The namespace was reached and the identity was accepted, but the queue or topic does not " +
                "exist. Check the entity name.",
            ServiceBusFailureReason.MessagingEntityDisabled =>
                "The namespace was reached and the identity was accepted, but the entity is disabled. " +
                "The network path is healthy.",
            ServiceBusFailureReason.UnauthorizedAccess =>
                "The namespace was reached but the identity is not authorised. Assign the Azure Service Bus " +
                "Data Sender role at the namespace or entity scope.",
            ServiceBusFailureReason.ServiceCommunicationProblem =>
                "The client could not communicate with the namespace. This is the signature of a blocked " +
                "outbound port. Retry over AMQP WebSockets on port 443.",
            ServiceBusFailureReason.ServiceTimeout =>
                "The service did not respond within the try timeout. Check for a firewall that silently " +
                "drops packets on the AMQP port.",
            ServiceBusFailureReason.ServiceBusy =>
                "The namespace throttled the request. The network path is healthy.",
            ServiceBusFailureReason.QuotaExceeded =>
                "A namespace or entity quota was exceeded. The network path is healthy.",
            _ =>
                "See the accompanying error message for the service-reported detail."
        };
    }
}
