using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Probes;

/// <summary>Establishes an AMQP link to an Azure Service Bus entity without sending anything.</summary>
public interface IServiceBusProbe
{
    /// <summary>Opens a link to the entity and reports the outcome.</summary>
    /// <param name="target">The Service Bus endpoint being diagnosed.</param>
    /// <param name="useWebSockets">Whether to tunnel AMQP over port 443 instead of port 5671.</param>
    /// <param name="timeout">The maximum time to wait for the link.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The Service Bus stage result.</returns>
    Task<StageResult> ProbeAsync(
        ProbeTarget target,
        bool useWebSockets,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}
