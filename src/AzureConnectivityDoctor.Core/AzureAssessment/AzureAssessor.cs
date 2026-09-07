using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Resources;
using AzureConnectivityDoctor.Core.Identity;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Security;
using Microsoft.Extensions.Logging;

namespace AzureConnectivityDoctor.Core.AzureAssessment;

/// <summary>
/// Reads the control-plane facts that explain a data-plane failure.
/// </summary>
/// <remarks>
/// <para>
/// The probes observe what happens on the wire. This class explains why. When a TCP connection
/// to an Azure SQL server times out, the decisive question is whether
/// <c>publicNetworkAccess</c> is <c>Disabled</c> and a private endpoint exists. That fact lives
/// in Azure Resource Manager and nowhere else.
/// </para>
/// <para>
/// <b>Read-only by construction.</b> The only operation performed is an HTTP <c>GET</c> of a
/// resource through <see cref="GenericResource"/>. No create, update, delete, tag or action
/// call is ever issued, so the Reader role is sufficient and the assessment cannot change
/// anything.
/// </para>
/// <para>
/// A generic resource read is used instead of a typed resource-provider SDK so that one code
/// path covers Azure SQL servers, Service Bus namespaces, storage accounts, Key Vaults and
/// anything else, without adding a package per service. The trade-off is that properties are
/// read from untyped JSON, so every lookup is defensive.
/// </para>
/// </remarks>
public sealed class AzureAssessor : IAzureAssessor
{
    private readonly ICredentialProvider _credentialProvider;
    private readonly ILogger<AzureAssessor> _logger;
    private readonly Lazy<ArmClient> _armClient;

    /// <summary>Creates the assessor.</summary>
    /// <param name="credentialProvider">Supplies the shared credential.</param>
    /// <param name="logger">The logger used for progress output.</param>
    public AzureAssessor(ICredentialProvider credentialProvider, ILogger<AzureAssessor> logger)
    {
        _credentialProvider = credentialProvider;
        _logger = logger;
        _armClient = new Lazy<ArmClient>(
            () => new ArmClient(_credentialProvider.GetCredential()),
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <inheritdoc />
    public async Task<StageResult> AssessAsync(string resourceId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceId);

        ResourceIdentifier identifier;
        try
        {
            identifier = new ResourceIdentifier(resourceId);
        }
        catch (FormatException exception)
        {
            return new StageResult
            {
                Stage = DiagnosticStage.AzureResourceAssessment,
                Outcome = DiagnosticOutcome.Failed,
                Summary =
                    $"'{resourceId}' is not a valid Azure resource ID. It must look like " +
                    "/subscriptions/<id>/resourceGroups/<name>/providers/<provider>/<type>/<name>.",
                ErrorType = nameof(FormatException),
                ErrorMessage = SecretRedactor.Redact(exception.Message)
            };
        }

        _logger.LogInformation("Reading Azure resource {ResourceId}", identifier);

        long start = Stopwatch.GetTimestamp();
        var evidence = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["resourceId"] = identifier.ToString(),
            ["accessMode"] = "read-only (HTTP GET)"
        };

        try
        {
            GenericResource resource = _armClient.Value.GetGenericResource(identifier);
            Response<GenericResource> response = await resource.GetAsync(cancellationToken);
            GenericResourceData data = response.Value.Data;
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            evidence["resourceName"] = data.Name ?? identifier.Name;
            evidence["resourceType"] = data.ResourceType.ToString();

            if (data.Location.HasValue)
            {
                evidence["location"] = data.Location.Value.Name;
            }

            IReadOnlyList<string> observations = ReadNetworkProperties(data.Properties, evidence);

            return new StageResult
            {
                Stage = DiagnosticStage.AzureResourceAssessment,
                Outcome = DiagnosticOutcome.Succeeded,
                Summary = observations.Count == 0
                    ? $"Read {identifier.Name}. It exposes no recognised network-access properties."
                    : $"Read {identifier.Name}: {string.Join("; ", observations)}.",
                DurationMilliseconds = elapsed,
                Evidence = evidence
            };
        }
        catch (RequestFailedException exception)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
            evidence["httpStatus"] = exception.Status.ToString(CultureInfo.InvariantCulture);
            evidence["errorCode"] = exception.ErrorCode ?? "(none)";
            evidence["interpretation"] = InterpretStatus(exception.Status);

            return new StageResult
            {
                Stage = DiagnosticStage.AzureResourceAssessment,
                Outcome = DiagnosticOutcome.Failed,
                Summary = $"Azure Resource Manager returned {exception.Status} for {identifier.Name}. " +
                    InterpretStatus(exception.Status),
                DurationMilliseconds = elapsed,
                ErrorType = nameof(RequestFailedException),
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            };
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            double elapsed = Stopwatch.GetElapsedTime(start).TotalMilliseconds;

            return new StageResult
            {
                Stage = DiagnosticStage.AzureResourceAssessment,
                Outcome = DiagnosticOutcome.Failed,
                Summary = $"The Azure Resource Manager read of {identifier.Name} did not complete.",
                DurationMilliseconds = elapsed,
                ErrorType = exception.GetType().Name,
                ErrorMessage = SecretRedactor.Redact(exception.Message),
                Evidence = evidence
            };
        }
    }

    /// <summary>
    /// Extracts the network-access properties that resource providers expose under common names.
    /// </summary>
    /// <param name="properties">The untyped <c>properties</c> object of the resource.</param>
    /// <param name="evidence">The dictionary to add findings to.</param>
    /// <returns>Short human-readable observations for the stage summary.</returns>
    internal static IReadOnlyList<string> ReadNetworkProperties(
        BinaryData? properties,
        Dictionary<string, string> evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        var observations = new List<string>();

        if (properties is null)
        {
            evidence["properties"] = "(the resource returned no properties object)";
            return observations;
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(properties);
        }
        catch (JsonException)
        {
            evidence["properties"] = "(the properties object could not be parsed as JSON)";
            return observations;
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return observations;
            }

            if (TryGetString(root, "publicNetworkAccess", out string? publicAccess))
            {
                evidence["publicNetworkAccess"] = publicAccess;
                observations.Add($"public network access is {publicAccess}");
            }

            if (TryGetString(root, "minimalTlsVersion", out string? minimalTls))
            {
                evidence["minimalTlsVersion"] = minimalTls;
                observations.Add($"the minimum TLS version is {minimalTls}");
            }

            if (TryGetString(root, "minimumTlsVersion", out string? minimumTls))
            {
                evidence["minimumTlsVersion"] = minimumTls;
            }

            if (root.TryGetProperty("privateEndpointConnections", out JsonElement connections)
                && connections.ValueKind == JsonValueKind.Array)
            {
                int count = connections.GetArrayLength();
                evidence["privateEndpointConnectionCount"] = count.ToString(CultureInfo.InvariantCulture);
                observations.Add(
                    count == 0
                        ? "no private endpoint connections exist"
                        : $"{count} private endpoint connection(s) exist");
            }

            if (root.TryGetProperty("networkAcls", out JsonElement acls)
                && acls.ValueKind == JsonValueKind.Object)
            {
                if (TryGetString(acls, "defaultAction", out string? defaultAction))
                {
                    evidence["networkAcls.defaultAction"] = defaultAction;
                    observations.Add($"the network ACL default action is {defaultAction}");
                }

                AddArrayCount(acls, "ipRules", "networkAcls.ipRuleCount", evidence);
                AddArrayCount(acls, "virtualNetworkRules", "networkAcls.virtualNetworkRuleCount", evidence);
            }

            AddArrayCount(root, "ipRules", "ipRuleCount", evidence);
            AddArrayCount(root, "virtualNetworkRules", "virtualNetworkRuleCount", evidence);
        }

        return observations;
    }

    private static void AddArrayCount(
        JsonElement parent,
        string propertyName,
        string evidenceKey,
        Dictionary<string, string> evidence)
    {
        if (parent.TryGetProperty(propertyName, out JsonElement array)
            && array.ValueKind == JsonValueKind.Array)
        {
            evidence[evidenceKey] = array.GetArrayLength().ToString(CultureInfo.InvariantCulture);
        }
    }

    private static bool TryGetString(JsonElement parent, string propertyName, out string value)
    {
        if (parent.TryGetProperty(propertyName, out JsonElement element)
            && element.ValueKind == JsonValueKind.String)
        {
            value = element.GetString() ?? string.Empty;
            return value.Length > 0;
        }

        value = string.Empty;
        return false;
    }

    private static string InterpretStatus(int status)
    {
        return status switch
        {
            401 => "The credential was not accepted. Check the tenant and the identity.",
            403 => "The identity is authenticated but lacks permission. Grant the Reader role on the resource.",
            404 => "The resource does not exist, or the signed-in identity cannot see the subscription.",
            429 => "Azure Resource Manager throttled the request. Retry shortly.",
            _ => "See the accompanying error message for the service-reported detail."
        };
    }
}
