using Azure.Core;
using Azure.Identity;
using AzureConnectivityDoctor.Core.Options;
using Microsoft.Extensions.Options;

namespace AzureConnectivityDoctor.Core.Identity;

/// <summary>
/// Creates a single <see cref="DefaultAzureCredential"/> for the whole process.
/// </summary>
/// <remarks>
/// <para>
/// One credential instance is shared deliberately. <see cref="DefaultAzureCredential"/> caches
/// both the discovered credential source and the acquired tokens; creating a new instance per
/// probe would repeat the whole discovery chain and, on a managed identity endpoint, would
/// issue an unnecessary token request for every target.
/// </para>
/// <para>
/// The credential chain includes an Azure CLI developer credential when the installed
/// <c>Azure.Identity</c> supports it. That is a library feature. This application never runs
/// the <c>az</c> executable, never reads Azure CLI files and works normally when the Azure CLI
/// is not installed.
/// </para>
/// <para>
/// Interactive browser sign-in is disabled. A diagnostic tool commonly runs on a headless
/// App Service instance, in a container or on a CI agent, where an interactive prompt would
/// hang until the timeout expires instead of failing fast with an actionable message.
/// </para>
/// </remarks>
public sealed class CredentialProvider : ICredentialProvider
{
    private readonly Lazy<TokenCredential> _credential;

    /// <summary>Creates the provider.</summary>
    /// <param name="options">The run options that carry the optional tenant and identity hints.</param>
    public CredentialProvider(IOptions<DoctorOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        DoctorOptions value = options.Value;

        _credential = new Lazy<TokenCredential>(
            () =>
            {
                var credentialOptions = new DefaultAzureCredentialOptions
                {
                    ExcludeInteractiveBrowserCredential = true
                };

                if (!string.IsNullOrWhiteSpace(value.TenantId))
                {
                    credentialOptions.TenantId = value.TenantId;
                }

                if (!string.IsNullOrWhiteSpace(value.ManagedIdentityClientId))
                {
                    credentialOptions.ManagedIdentityClientId = value.ManagedIdentityClientId;
                }

                return new DefaultAzureCredential(credentialOptions);
            },
            LazyThreadSafetyMode.ExecutionAndPublication);
    }

    /// <inheritdoc />
    public TokenCredential GetCredential()
    {
        return _credential.Value;
    }
}
