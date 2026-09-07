using AzureConnectivityDoctor.Core.Options;

namespace AzureConnectivityDoctor.Cli;

/// <summary>
/// The outcome of reading the command line.
/// </summary>
/// <remarks>
/// A bad command line is an expected condition, so it is modelled as a value rather than an
/// exception. This also makes the parser trivially unit testable without launching a process.
/// </remarks>
internal sealed record CommandLineParseResult
{
    private CommandLineParseResult()
    {
    }

    /// <summary>Whether the command line was valid.</summary>
    internal bool Succeeded { get; private init; }

    /// <summary>The options to run with, when <see cref="Succeeded"/> is true.</summary>
    internal DoctorOptions? Options { get; private init; }

    /// <summary>Why the command line was rejected, when <see cref="Succeeded"/> is false.</summary>
    internal string? Error { get; private init; }

    /// <summary>Whether the caller asked for the help screen.</summary>
    internal bool ShowHelp { get; private init; }

    /// <summary>Whether the caller asked for the version.</summary>
    internal bool ShowVersion { get; private init; }

    /// <summary>Whether debug-level logging was requested.</summary>
    internal bool Verbose { get; private init; }

    internal static CommandLineParseResult Success(DoctorOptions options, bool verbose)
    {
        return new CommandLineParseResult { Succeeded = true, Options = options, Verbose = verbose };
    }

    internal static CommandLineParseResult Failure(string error)
    {
        return new CommandLineParseResult { Succeeded = false, Error = error };
    }

    internal static CommandLineParseResult Help()
    {
        return new CommandLineParseResult { Succeeded = true, ShowHelp = true };
    }

    internal static CommandLineParseResult Version()
    {
        return new CommandLineParseResult { Succeeded = true, ShowVersion = true };
    }
}
