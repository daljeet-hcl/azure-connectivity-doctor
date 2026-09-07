using Azure.Core;

namespace AzureConnectivityDoctor.Core.Identity;

/// <summary>Supplies the single <see cref="TokenCredential"/> used by every authenticated probe.</summary>
public interface ICredentialProvider
{
    /// <summary>Gets the credential, creating it once on first use.</summary>
    /// <returns>A shared, thread-safe credential.</returns>
    TokenCredential GetCredential();
}
