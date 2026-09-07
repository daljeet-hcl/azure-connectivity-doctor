using System.Reflection;
using AzureConnectivityDoctor.Core.DependencyInjection;
using AzureConnectivityDoctor.Core.Execution;
using AzureConnectivityDoctor.Core.Model;
using AzureConnectivityDoctor.Core.Options;
using AzureConnectivityDoctor.Core.Reporting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

namespace AzureConnectivityDoctor.Cli;

/// <summary>
/// The entry point.
/// </summary>
/// <remarks>
/// <para>
/// Diagnostic logs are written to standard error and the Markdown report is written to standard
/// output. That separation lets an operator pipe the report somewhere useful without the logs
/// contaminating it.
/// </para>
/// <para>
/// Ctrl+C is handled cooperatively: the first press cancels the token and the run still produces
/// a partial report describing exactly how far it got.
/// </para>
/// </remarks>
internal static class Program
{
    /// <summary>Runs the tool.</summary>
    /// <param name="args">The command-line arguments.</param>
    /// <returns>One of the values in <see cref="ExitCodes"/>.</returns>
    internal static async Task<int> Main(string[] args)
    {
        CommandLineParseResult parsed = CommandLineParser.Parse(args);

        if (parsed.ShowHelp)
        {
            Console.Out.WriteLine(HelpText.Usage);
            return ExitCodes.Success;
        }

        if (parsed.ShowVersion)
        {
            Console.Out.WriteLine(ResolveVersion());
            return ExitCodes.Success;
        }

        if (!parsed.Succeeded || parsed.Options is null)
        {
            Console.Error.WriteLine(parsed.Error ?? "The command line was invalid.");
            Console.Error.WriteLine(HelpText.ShortUsage);
            return ExitCodes.UsageError;
        }

        DoctorOptions options = parsed.Options;

        using var cancellation = new CancellationTokenSource();

        Console.CancelKeyPress += (_, eventArgs) =>
        {
            // Cancel the run rather than killing the process, so a partial report is still written.
            eventArgs.Cancel = true;
            Console.Error.WriteLine("Cancellation requested. Finishing the current stages...");

            if (!cancellation.IsCancellationRequested)
            {
                cancellation.Cancel();
            }
        };

        try
        {
            return await RunAsync(options, parsed.Verbose, cancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("The run was cancelled.");
            return ExitCodes.Cancelled;
        }
        catch (Exception exception)
        {
            // A diagnostic tool must never end with an unhandled stack trace on an operator's
            // screen; the message plus a distinct exit code is what a pipeline can act on.
            Console.Error.WriteLine($"The tool failed unexpectedly: {exception.Message}");
            return ExitCodes.InternalError;
        }
    }

    private static async Task<int> RunAsync(
        DoctorOptions options,
        bool verbose,
        CancellationToken cancellationToken)
    {
        HostApplicationBuilder builder = Host.CreateApplicationBuilder();

        builder.Logging.ClearProviders();
        builder.Logging.SetMinimumLevel(verbose ? LogLevel.Debug : LogLevel.Information);
        builder.Logging.AddSimpleConsole(console =>
        {
            console.SingleLine = true;
            console.TimestampFormat = "HH:mm:ss ";
            console.UseUtcTimestamp = true;
        });

        // Send every log line to standard error so that standard output carries only the report.
        builder.Services.Configure<ConsoleLoggerOptions>(
            console => console.LogToStandardErrorThreshold = LogLevel.Trace);

        // Azure SDK and SqlClient loggers are noisy at Information level and add nothing here.
        builder.Logging.AddFilter("Azure", LogLevel.Warning);
        builder.Logging.AddFilter("Microsoft", LogLevel.Warning);

        builder.Services.AddSingleton(Microsoft.Extensions.Options.Options.Create(options));
        builder.Services.AddConnectivityDoctorCore();

        using IHost host = builder.Build();

        IDiagnosticRunner runner = host.Services.GetRequiredService<IDiagnosticRunner>();
        RunReport report = await runner.RunAsync(cancellationToken).ConfigureAwait(false);

        IReadOnlyList<IReportRenderer> renderers =
            [.. host.Services.GetServices<IReportRenderer>()];

        await WriteReportsAsync(report, options, renderers, cancellationToken).ConfigureAwait(false);

        if (report.Cancelled)
        {
            return ExitCodes.Cancelled;
        }

        return report.HighestSeverity == FindingSeverity.Error
            ? ExitCodes.ConnectivityFailure
            : ExitCodes.Success;
    }

    private static async Task WriteReportsAsync(
        RunReport report,
        DoctorOptions options,
        IReadOnlyList<IReportRenderer> renderers,
        CancellationToken cancellationToken)
    {
        string markdown = Render(renderers, ReportFormat.Markdown, report);
        string json = Render(renderers, ReportFormat.Json, report);

        if (options.PrintToConsole)
        {
            Console.Out.WriteLine(markdown);
        }

        // The report files are written even when the run was cancelled: a partial report is the
        // most valuable artefact an operator has after an interrupted investigation.
        if (!string.IsNullOrWhiteSpace(options.MarkdownOutputPath))
        {
            await WriteFileAsync(options.MarkdownOutputPath, markdown, cancellationToken)
                .ConfigureAwait(false);
            Console.Error.WriteLine($"Markdown report written to {options.MarkdownOutputPath}");
        }

        if (!string.IsNullOrWhiteSpace(options.JsonOutputPath))
        {
            await WriteFileAsync(options.JsonOutputPath, json, cancellationToken).ConfigureAwait(false);
            Console.Error.WriteLine($"JSON report written to {options.JsonOutputPath}");
        }
    }

    private static async Task WriteFileAsync(string path, string content, CancellationToken cancellationToken)
    {
        string? directory = Path.GetDirectoryName(Path.GetFullPath(path));

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // CancellationToken.None: cancelling the write would leave a truncated report behind,
        // which is worse than the few milliseconds the write costs.
        _ = cancellationToken;
        await File.WriteAllTextAsync(path, content, CancellationToken.None).ConfigureAwait(false);
    }

    private static string Render(
        IReadOnlyList<IReportRenderer> renderers,
        ReportFormat format,
        RunReport report)
    {
        foreach (IReportRenderer renderer in renderers)
        {
            if (renderer.Format == format)
            {
                return renderer.Render(report);
            }
        }

        throw new InvalidOperationException($"No renderer is registered for the {format} format.");
    }

    private static string ResolveVersion()
    {
        Assembly assembly = typeof(Program).Assembly;

        string? informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (string.IsNullOrEmpty(informational))
        {
            return assembly.GetName().Version?.ToString() ?? "unknown";
        }

        int plusIndex = informational.IndexOf('+', StringComparison.Ordinal);
        return plusIndex < 0 ? informational : informational[..plusIndex];
    }
}
