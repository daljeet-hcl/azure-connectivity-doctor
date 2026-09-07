namespace AzureConnectivityDoctor.Core.Model;

/// <summary>
/// How strongly the collected evidence supports a <see cref="Finding"/>.
/// </summary>
/// <remarks>
/// This exists so the tool never states an inference as if it were a measurement.
/// A refused TCP connection is <see cref="Observed"/>. "Your subnet has no NSG rule for
/// port 1433" would only ever be <see cref="Inferred"/>, because the tool cannot see the
/// network security group from inside the workload.
/// </remarks>
public enum EvidenceConfidence
{
    /// <summary>Directly measured by this tool in this run.</summary>
    Observed = 0,

    /// <summary>Read from an authoritative Azure API in this run.</summary>
    Verified = 1,

    /// <summary>Deduced from observed evidence. Plausible, not proven.</summary>
    Inferred = 2,

    /// <summary>Two pieces of evidence disagree.</summary>
    Conflicting = 3,

    /// <summary>The evidence needed to decide could not be collected.</summary>
    Unavailable = 4
}
