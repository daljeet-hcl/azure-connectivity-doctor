namespace AzureConnectivityDoctor.Core.Endpoints;

/// <summary>
/// Turns the free-form endpoint text supplied by an operator into a normalised
/// <see cref="Model.ProbeTarget"/>.
/// </summary>
public interface IEndpointParser
{
    /// <summary>Parses one endpoint string.</summary>
    /// <param name="value">The raw endpoint text, for example <c>https://example.com</c>.</param>
    /// <returns>The parse result. Never <see langword="null"/>.</returns>
    TargetParseResult Parse(string value);
}
