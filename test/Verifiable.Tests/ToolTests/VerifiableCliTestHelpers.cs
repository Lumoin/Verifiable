using System.CommandLine;
using System.Diagnostics;

namespace Verifiable.Tests.ToolTests;

/// <summary>
/// Result of running a CLI command.
/// </summary>
/// <param name="ExitCode">The process exit code. Zero indicates success.</param>
/// <param name="Stdout">The standard output captured from the process.</param>
/// <param name="Stderr">The standard error captured from the process.</param>
internal readonly record struct CliResult(int ExitCode, string Stdout, string Stderr);

/// <summary>
/// Shared test infrastructure and helper methods for test classes.
/// </summary>
internal static class VerifiableCliTestHelpers
{
    /// <summary>
    /// Characters that have special meaning in System.CommandLine parsing.
    /// These are intentional parser features (e.g. @ for response files, &lt; &gt; for redirection).
    /// </summary>
    private static char[] CliSpecialCharacters { get; } =
    [
        ' ', '"', '\'', '`', '|', '$', ';', '&', '<', '>', '\\', '@'
    ];


    /// <summary>
    /// Checks if a string contains characters that have special meaning in CLI parsing.
    /// </summary>
    public static bool ContainsCliSpecialCharacters(string value)
    {
        return value.AsSpan().IndexOfAny(CliSpecialCharacters) >= 0;
    }


    /// <summary>
    /// Checks if a string is unsuitable for unquoted CLI argument use.
    /// </summary>
    public static bool IsUnsuitableForCliArgument(string value)
    {
        return string.IsNullOrWhiteSpace(value) || ContainsCliSpecialCharacters(value);
    }


    /// <summary>
    /// Checks if a string is unsuitable for CLI option value use.
    /// </summary>
    public static bool IsUnsuitableForCliOptionValue(string value)
    {
        return ContainsCliSpecialCharacters(value) || value.StartsWith('-');
    }


    /// <summary>
    /// Determines whether the input starts with a System.CommandLine built-in option prefix.
    /// These are framework-provided options (help, version) that parse without errors.
    /// Includes both Unix-style (-h, --help) and Windows-style (/h, /?) prefixes.
    /// </summary>
    public static bool StartsWithSystemCommandLineBuiltInOption(string input)
    {
        return input.StartsWith("-h", StringComparison.OrdinalIgnoreCase) ||
               input.StartsWith("-?", StringComparison.Ordinal) ||
               input.StartsWith("--help", StringComparison.OrdinalIgnoreCase) ||
               input.StartsWith("--version", StringComparison.OrdinalIgnoreCase) ||
               input.StartsWith("/h", StringComparison.OrdinalIgnoreCase) ||
               input.StartsWith("/?", StringComparison.Ordinal);
    }


    /// <summary>
    /// Builds a testable root command that mirrors the structure in Program.cs.
    /// </summary>
    public static RootCommand BuildTestableRootCommand(
        out Argument<int> createIdArgument,
        out Argument<string> createParamArgument,
        out Option<string?> extraParamOption,
        out Argument<int> revokeIdArgument,
        out Argument<int> viewIdArgument,
        out Command didCreateCommand,
        out Command didRevokeCommand,
        out Command didListCommand,
        out Command didViewCommand,
        out Command infoTpmCommand)
    {
        RootCommand rootCommand = new("A command line tool for security elements, DIDs and VCs");

        Command didCommand = new("did", "Create, revoke, list or view DIDs.");
        rootCommand.Subcommands.Add(didCommand);

        createIdArgument = new("id") { Description = "Identifier for the new DID document." };
        createParamArgument = new("param") { Description = "New DID document parameter." };
        extraParamOption = new("--extraParam", "-e") { Description = "Some extra parameter." };

        didCreateCommand = new("create", "Create a new DID document.")
        {
            createIdArgument,
            createParamArgument,
            extraParamOption
        };
        didCreateCommand.Aliases.Add("new");
        didCommand.Subcommands.Add(didCreateCommand);

        revokeIdArgument = new("id") { Description = "Identifier to revoke a DID document." };
        didRevokeCommand = new("revoke", "Revoke a DID document.")
        {
            revokeIdArgument
        };
        didCommand.Subcommands.Add(didRevokeCommand);

        didListCommand = new("list", "List all DID documents.");
        didCommand.Subcommands.Add(didListCommand);

        viewIdArgument = new("id") { Description = "DID identifier for a document to view." };
        didViewCommand = new("view", "View DID document.")
        {
            viewIdArgument
        };
        didCommand.Subcommands.Add(didViewCommand);

        Command infoCommand = new("info", "Print selected platform information (only Tpm currently).");
        rootCommand.Subcommands.Add(infoCommand);

        infoTpmCommand = new("Tpm", "Print trusted platform module (TPM) information.");
        infoCommand.Subcommands.Add(infoTpmCommand);

        return rootCommand;
    }


    /// <summary>
    /// Simplified overload for tests that only need a subset of arguments.
    /// </summary>
    public static RootCommand BuildTestableRootCommand(
        out Argument<int> createIdArgument,
        out Argument<string> createParamArgument,
        out Option<string?> extraParamOption)
    {
        return BuildTestableRootCommand(
            out createIdArgument,
            out createParamArgument,
            out extraParamOption,
            out _,
            out _,
            out _,
            out _,
            out _,
            out _,
            out _);
    }


    /// <summary>
    /// Gets the path to the built executable, or null if not found.
    /// </summary>
    public static string? GetExecutablePath()
    {
        string basePath = AppContext.BaseDirectory;
        string projectRoot = Path.GetFullPath(Path.Combine(basePath, "../../../../.."));

        string[] configurations = ["Debug", "Release"];
        string[] projectPaths = ["src/Verifiable", "Verifiable"];
        string extension = OperatingSystem.IsWindows() ? ".exe" : "";

        foreach(var projectPath in projectPaths)
        {
            foreach(var config in configurations)
            {
                string path = Path.Combine(projectRoot, projectPath, "bin", config, "net10.0", $"verifiable{extension}");
                if(File.Exists(path))
                {
                    return path;
                }
            }
        }

        return null;
    }


    /// <summary>
    /// Creates a process configured for MCP server testing with stdio redirection.
    /// </summary>
    public static Process CreateMcpServerProcess(string executablePath)
    {
        return new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = "-mcp",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };
    }


    /// <summary>
    /// Ensures an MCP server process is terminated.
    /// </summary>
    public static async Task EnsureProcessTerminatedAsync(Process process, CancellationToken cancellationToken = default)
    {
        if(!process.HasExited)
        {
            process.Kill();
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Reads a line from a stream reader with timeout support.
    /// </summary>
    public static async Task<string?> ReadLineWithTimeoutAsync(
        StreamReader reader,
        CancellationToken cancellationToken)
    {
        try
        {
            return await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            return null;
        }
    }


    /// <summary>
    /// Runs the CLI executable with the specified arguments and returns the result.
    /// </summary>
    public static async Task<CliResult> RunCliAsync(
        string executablePath,
        string arguments,
        CancellationToken cancellationToken = default)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        process.Start();

        string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        return new CliResult(process.ExitCode, stdout, stderr);
    }


    /// <summary>
    /// Runs the CLI executable with the specified argument array and returns the result.
    /// </summary>
    public static async Task<CliResult> RunCliAsync(
        string executablePath,
        string[] arguments,
        CancellationToken cancellationToken = default)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        foreach(var arg in arguments)
        {
            process.StartInfo.ArgumentList.Add(arg);
        }

        process.Start();

        string stdout = await process.StandardOutput.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        string stderr = await process.StandardError.ReadToEndAsync(cancellationToken).ConfigureAwait(false);

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        return new CliResult(process.ExitCode, stdout, stderr);
    }
}