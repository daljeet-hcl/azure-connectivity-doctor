using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Endpoints;

/// <summary>
/// The outcome of parsing one endpoint string.
/// </summary>
/// <remarks>
/// Parsing failure is an expected, routine result — operators mistype endpoints — so it is
/// modelled as a value rather than an exception. Exceptions are reserved for programmer errors.
/// </remarks>
public sealed record TargetParseResult
{
    private TargetParseResult()
    {
    }

    /// <summary>Whether the endpoint was parsed successfully.</summary>
    public bool Succeeded { get; private init; }

    /// <summary>The parsed target, present only when <see cref="Succeeded"/> is true.</summary>
    public ProbeTarget? Target { get; private init; }

    /// <summary>The reason parsing failed, present only when <see cref="Succeeded"/> is false.</summary>
    public string? Error { get; private init; }

    /// <summary>Creates a successful result.</summary>
    /// <param name="target">The parsed target.</param>
    /// <returns>A successful <see cref="TargetParseResult"/>.</returns>
    public static TargetParseResult Success(ProbeTarget target)
    {
        return new TargetParseResult { Succeeded = true, Target = target };
    }

    /// <summary>Creates a failed result.</summary>
    /// <param name="error">A message explaining what was wrong with the input.</param>
    /// <returns>A failed <see cref="TargetParseResult"/>.</returns>
    public static TargetParseResult Failure(string error)
    {
        return new TargetParseResult { Succeeded = false, Error = error };
    }
}
