using System.Runtime.InteropServices;
using AzureConnectivityDoctor.Core.Model;

namespace AzureConnectivityDoctor.Core.Execution;

/// <summary>
/// Describes the environment the tool is running in.
/// </summary>
/// <remarks>
/// Detection relies only on environment variables that the respective platforms document as
/// being present. Nothing here is a security control; it exists purely so that a report read
/// three weeks later still says where the measurements were taken from.
/// </remarks>
public static class RuntimeContextProvider
{
    /// <summary>Builds a description of the current runtime environment.</summary>
    /// <returns>The runtime context for the current process.</returns>
    public static RuntimeContext Capture()
    {
        return new RuntimeContext
        {
            OperatingSystem = RuntimeInformation.OSDescription.Trim(),
            ProcessArchitecture = RuntimeInformation.ProcessArchitecture.ToString(),
            FrameworkDescription = RuntimeInformation.FrameworkDescription.Trim(),
            DetectedPlatform = DetectPlatform()
        };
    }

    private static string DetectPlatform()
    {
        // Azure App Service and Azure Functions both set WEBSITE_INSTANCE_ID.
        if (HasValue("WEBSITE_INSTANCE_ID"))
        {
            return HasValue("FUNCTIONS_WORKER_RUNTIME") ? "AzureFunctions" : "AzureAppService";
        }

        // Azure Container Apps injects the replica and app name.
        if (HasValue("CONTAINER_APP_NAME") || HasValue("CONTAINER_APP_REPLICA_NAME"))
        {
            return "AzureContainerApps";
        }

        // Kubernetes injects the default service host into every pod.
        if (HasValue("KUBERNETES_SERVICE_HOST"))
        {
            return "Kubernetes";
        }

        if (HasValue("GITHUB_ACTIONS"))
        {
            return "GitHubActions";
        }

        if (HasValue("TF_BUILD"))
        {
            return "AzurePipelines";
        }

        if (HasValue("CODESPACES"))
        {
            return "GitHubCodespaces";
        }

        if (File.Exists("/.dockerenv"))
        {
            return "Container";
        }

        return "Unknown";
    }

    private static bool HasValue(string variable)
    {
        return !string.IsNullOrEmpty(Environment.GetEnvironmentVariable(variable));
    }
}
