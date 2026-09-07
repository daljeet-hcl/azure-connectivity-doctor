using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Reporting;

/// <summary>
/// Serialises the run to JSON for machine consumption.
/// </summary>
/// <remarks>
/// <para>
/// Enumerations are written as names rather than numbers. A pipeline that greps for
/// <c>"outcome": "Failed"</c> keeps working when a new enumeration member is inserted, whereas
/// one that matches on an integer silently breaks.
/// </para>
/// <para>
/// The serializer options are static and shared. Creating <see cref="JsonSerializerOptions"/>
/// per call defeats the reflection cache that <c>System.Text.Json</c> builds on first use.
/// </para>
/// </remarks>
public sealed class JsonReportRenderer : IReportRenderer
{
    /// <summary>The serializer options used for the JSON report, exposed for tests.</summary>
    public static readonly JsonSerializerOptions SerializerOptions = CreateOptions();

    /// <inheritdoc />
    public ReportFormat Format => ReportFormat.Json;

    /// <inheritdoc />
    public string Render(RunReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return JsonSerializer.Serialize(report, SerializerOptions);
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,

            // The report contains host names and certificate subjects. The relaxed encoder keeps
            // them readable instead of escaping every non-alphanumeric character. The output is
            // written to a file and never embedded in HTML.
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        options.Converters.Add(new JsonStringEnumConverter());
        return options;
    }
}
