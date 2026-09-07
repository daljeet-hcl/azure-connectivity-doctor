using System.Net;
using AzureConnectivityDoctor.Core.Analysis;
using AzureConnectivityDoctor.Core.AzureAssessment;
using AzureConnectivityDoctor.Core.Endpoints;
using AzureConnectivityDoctor.Core.Execution;
using AzureConnectivityDoctor.Core.Identity;
using AzureConnectivityDoctor.Core.Probes;
using AzureConnectivityDoctor.Core.Reporting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AzureConnectivityDoctor.Core.DependencyInjection;

/// <summary>
/// Registers every service the diagnostic pipeline needs.
/// </summary>
/// <remarks>
/// A single composition root keeps the host wiring in one reviewable place. Java readers can
/// think of this as the Spring <c>@Configuration</c> class for the library.
/// </remarks>
public static class ServiceCollectionExtensions
{
    /// <summary>The user agent sent by the HTTP probe.</summary>
    private const string UserAgent = "azure-connectivity-doctor";

    /// <summary>Adds the parser, probes, analyzer, renderers and runner.</summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, to allow chaining.</returns>
    public static IServiceCollection AddConnectivityDoctorCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<IEndpointParser, EndpointParser>();
        services.TryAddSingleton<IDnsProbe, DnsProbe>();
        services.TryAddSingleton<ITcpProbe, TcpProbe>();
        services.TryAddSingleton<ITlsProbe, TlsProbe>();
        services.TryAddSingleton<IHttpProbe, HttpProbe>();
        services.TryAddSingleton<ISqlProbe, SqlProbe>();
        services.TryAddSingleton<IServiceBusProbe, ServiceBusProbe>();

        services.TryAddSingleton<ICredentialProvider, CredentialProvider>();
        services.TryAddSingleton<ITokenProbe, TokenProbe>();
        services.TryAddSingleton<IAzureAssessor, AzureAssessor>();

        services.TryAddSingleton<IRootCauseAnalyzer, RootCauseAnalyzer>();
        services.TryAddSingleton<IDiagnosticRunner, DiagnosticRunner>();

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IReportRenderer, MarkdownReportRenderer>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IReportRenderer, JsonReportRenderer>());

        services
            .AddHttpClient(
                HttpProbe.HttpClientName,
                client =>
                {
                    // The probe applies its own per-request timeout through a linked token, so the
                    // client-level timeout is disabled to avoid two competing deadlines.
                    client.Timeout = Timeout.InfiniteTimeSpan;
                    client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
                })
            .ConfigurePrimaryHttpMessageHandler(
                () => new SocketsHttpHandler
                {
                    // Redirects are not followed: a 301 or 302 is itself diagnostic evidence about
                    // the endpoint and following it would silently probe a different host.
                    AllowAutoRedirect = false,
                    AutomaticDecompression = DecompressionMethods.All,
                    PooledConnectionLifetime = TimeSpan.FromMinutes(2)
                });

        return services;
    }
}
