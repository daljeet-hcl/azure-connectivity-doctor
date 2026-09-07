using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using AzureConnectivityDoctor.Core.Options;

namespace AzureConnectivityDoctor.Cli;

/// <summary>
/// Reads the command line into a <see cref="DoctorOptions"/>.
/// </summary>
/// <remarks>
/// <para>
/// The parser is written by hand rather than taken from a command-line library. The option set
/// is small and stable, and a hand-written parser keeps the dependency surface of a security
/// diagnostic tool minimal and keeps the exact behaviour reviewable in one file.
/// </para>
/// <para>
/// No option accepts a password, key, token or connection string. That is deliberate: command
/// lines end up in shell history, process listings and CI logs.
/// </para>
/// </remarks>
internal static class CommandLineParser
{
    /// <summary>Parses the arguments.</summary>
    /// <param name="args">The raw arguments, excluding the executable name.</param>
    /// <returns>The parse result. Never <see langword="null"/>.</returns>
    internal static CommandLineParseResult Parse(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (args.Length == 0)
        {
            return CommandLineParseResult.Help();
        }

        List<string> endpoints = [];
        List<string> resourceIds = [];
        string? endpointsFile = null;
        TimeSpan timeout = TimeSpan.FromSeconds(10);
        TimeSpan overallTimeout = TimeSpan.FromMinutes(5);
        int concurrency = 4;
        bool enableHttp = false;
        bool enableIdentity = false;
        bool enableAzureAssessment = false;
        string? tenantId = null;
        string? clientId = null;
        string? jsonPath = "connectivity-report.json";
        string? markdownPath = "connectivity-report.md";
        bool printToConsole = true;
        bool verbose = false;

        for (int index = 0; index < args.Length; index++)
        {
            string argument = args[index];

            switch (argument)
            {
                case "-h":
                case "--help":
                    return CommandLineParseResult.Help();

                case "--version":
                    return CommandLineParseResult.Version();

                case "--http":
                    enableHttp = true;
                    break;

                case "--identity":
                    enableIdentity = true;
                    break;

                case "--azure-assessment":
                    enableAzureAssessment = true;
                    break;

                case "--quiet":
                    printToConsole = false;
                    break;

                case "--verbose":
                    verbose = true;
                    break;

                case "--no-json":
                    jsonPath = null;
                    break;

                case "--no-markdown":
                    markdownPath = null;
                    break;

                case "--endpoint":
                    if (!TryReadValue(args, ref index, out string? endpoint))
                    {
                        return MissingValue(argument);
                    }

                    endpoints.Add(endpoint);
                    break;

                case "--endpoints-file":
                    if (!TryReadValue(args, ref index, out endpointsFile))
                    {
                        return MissingValue(argument);
                    }

                    break;

                case "--resource-id":
                    if (!TryReadValue(args, ref index, out string? resourceId))
                    {
                        return MissingValue(argument);
                    }

                    resourceIds.Add(resourceId);
                    break;

                case "--tenant-id":
                    if (!TryReadValue(args, ref index, out tenantId))
                    {
                        return MissingValue(argument);
                    }

                    break;

                case "--client-id":
                    if (!TryReadValue(args, ref index, out clientId))
                    {
                        return MissingValue(argument);
                    }

                    break;

                case "--json":
                    if (!TryReadValue(args, ref index, out jsonPath))
                    {
                        return MissingValue(argument);
                    }

                    break;

                case "--markdown":
                    if (!TryReadValue(args, ref index, out markdownPath))
                    {
                        return MissingValue(argument);
                    }

                    break;

                case "--timeout":
                    if (!TryReadValue(args, ref index, out string? timeoutText))
                    {
                        return MissingValue(argument);
                    }

                    if (!TryParseSeconds(timeoutText, minimum: 1, out timeout))
                    {
                        return CommandLineParseResult.Failure(
                            $"--timeout must be a whole number of seconds of at least 1, but was '{timeoutText}'.");
                    }

                    break;

                case "--overall-timeout":
                    if (!TryReadValue(args, ref index, out string? overallText))
                    {
                        return MissingValue(argument);
                    }

                    if (!TryParseSeconds(overallText, minimum: 0, out overallTimeout))
                    {
                        return CommandLineParseResult.Failure(
                            $"--overall-timeout must be a whole number of seconds of at least 0, but was '{overallText}'.");
                    }

                    break;

                case "--concurrency":
                    if (!TryReadValue(args, ref index, out string? concurrencyText))
                    {
                        return MissingValue(argument);
                    }

                    if (!int.TryParse(concurrencyText, NumberStyles.Integer, CultureInfo.InvariantCulture, out concurrency)
                        || concurrency < 1
                        || concurrency > 64)
                    {
                        return CommandLineParseResult.Failure(
                            $"--concurrency must be a whole number between 1 and 64, but was '{concurrencyText}'.");
                    }

                    break;

                default:
                    if (argument.StartsWith('-'))
                    {
                        return CommandLineParseResult.Failure($"Unknown option '{argument}'.");
                    }

                    endpoints.Add(argument);
                    break;
            }
        }

        if (endpoints.Count == 0 && string.IsNullOrWhiteSpace(endpointsFile))
        {
            return CommandLineParseResult.Failure(
                "No endpoint was supplied. Pass at least one endpoint or use --endpoints-file.");
        }

        if (enableAzureAssessment && resourceIds.Count == 0)
        {
            return CommandLineParseResult.Failure(
                "--azure-assessment requires at least one --resource-id.");
        }

        var options = new DoctorOptions
        {
            Endpoints = endpoints,
            EndpointsFile = endpointsFile,
            Timeout = timeout,
            OverallTimeout = overallTimeout,
            MaxConcurrency = concurrency,
            EnableHttp = enableHttp,
            EnableIdentity = enableIdentity,
            EnableAzureAssessment = enableAzureAssessment,
            ResourceIds = resourceIds,
            JsonOutputPath = jsonPath,
            MarkdownOutputPath = markdownPath,
            PrintToConsole = printToConsole,
            TenantId = tenantId,
            ManagedIdentityClientId = clientId
        };

        return CommandLineParseResult.Success(options, verbose);
    }

    /// <summary>
    /// Reads the value that follows an option and advances the index past it.
    /// </summary>
    /// <param name="args">The raw arguments.</param>
    /// <param name="index">The index of the option; advanced to the value on success.</param>
    /// <param name="value">The value read, or <see langword="null"/> when there is none.</param>
    /// <returns><see langword="true"/> when a non-blank value was read.</returns>
    /// <remarks>
    /// The out parameter is declared nullable with <see cref="NotNullWhenAttribute"/> so that a
    /// single method serves both call sites that assign to a <c>string?</c> variable and call
    /// sites that need a non-null <c>string</c>. Overloading on out-parameter nullability alone
    /// is not legal, because nullability is not part of a method signature.
    /// </remarks>
    private static bool TryReadValue(string[] args, ref int index, [NotNullWhen(true)] out string? value)
    {
        if (index + 1 >= args.Length)
        {
            value = null;
            return false;
        }

        string candidate = args[index + 1];
        if (string.IsNullOrWhiteSpace(candidate))
        {
            value = null;
            return false;
        }

        index++;
        value = candidate;
        return true;
    }

    private static bool TryParseSeconds(string? text, int minimum, out TimeSpan value)
    {
        value = TimeSpan.Zero;

        if (!int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int seconds)
            || seconds < minimum
            || seconds > 86_400)
        {
            return false;
        }

        value = TimeSpan.FromSeconds(seconds);
        return true;
    }

    private static CommandLineParseResult MissingValue(string option)
    {
        return CommandLineParseResult.Failure($"Option '{option}' requires a value.");
    }
}
