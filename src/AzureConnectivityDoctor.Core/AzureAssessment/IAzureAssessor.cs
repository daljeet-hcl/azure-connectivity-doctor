using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.AzureAssessment;

/// <summary>Reads network-relevant configuration from Azure Resource Manager.</summary>
public interface IAzureAssessor
{
    /// <summary>Reads one resource and summarises its network configuration.</summary>
    /// <param name="resourceId">The full Azure resource ID.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The assessment stage result.</returns>
    Task<StageResult> AssessAsync(string resourceId, CancellationToken cancellationToken);
}
