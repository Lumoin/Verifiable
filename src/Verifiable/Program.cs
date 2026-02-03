using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.CommandLine;
using System.Threading.Tasks;

namespace Verifiable;

/// <summary>
/// A console program for DID and VC documents.
/// </summary>
public static class Program
{
    /// <summary>
    /// An entry point to a console program for DID and VC documents.
    /// </summary>
    /// <param name="args">The arguments to the program.</param>
    /// <returns>The exit code from the program.</returns>
    public static async Task<int> Main(string[] args)
    {
        if(args.Length == 1 && args[0] == "-mcp")
        {
            return await RunMcpServerAsync(args);
        }

        return await RunCliAsync(args);
    }

    private static async Task<int> RunMcpServerAsync(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddMcpServer()
            .WithStdioServerTransport()
            .WithTools<VerifiableMcpServer>();

        builder.Logging.AddConsole(options =>
        {
            options.LogToStandardErrorThreshold = LogLevel.Trace;
        });

        await builder.Build().RunAsync();

        return 0;
    }

    private static async Task<int> RunCliAsync(string[] args)
    {
        RootCommand rootCommand = new("A command line tool for security elements, DIDs and VCs");

        //Global option for disabling colors.
        Option<bool> noColorOption = new("--no-color") { Description = "Disable colored output." };
        rootCommand.Options.Add(noColorOption);

        Command didCommand = new("did", "Create, revoke, list or view DIDs.");
        rootCommand.Subcommands.Add(didCommand);

        Argument<int> createIdArgument = new("id") { Description = "Identifier for the new DID document." };
        Argument<string> createParamArgument = new("param") { Description = "New DID document parameter." };
        Option<string?> extraParamOption = new("--extraParam", "-e") { Description = "Some extra parameter." };

        Command didCreateCommand = new("create", "Create a new DID document.")
        {
            createIdArgument,
            createParamArgument,
            extraParamOption
        };
        didCreateCommand.Aliases.Add("new");
        didCommand.Subcommands.Add(didCreateCommand);

        didCreateCommand.SetAction(parseResult =>
        {
            int id = parseResult.GetValue(createIdArgument);
            string? param = parseResult.GetValue(createParamArgument);
            string? extraParam = parseResult.GetValue(extraParamOption);

            var result = VerifiableOperations.CreateDid(id, param ?? string.Empty, extraParam);
            Console.WriteLine(result.Value);

            return 0;
        });

        Argument<int> revokeIdArgument = new("id") { Description = "Identifier to revoke a DID document." };

        Command didRevokeCommand = new("revoke", "Revoke a DID document.")
        {
            revokeIdArgument
        };
        didCommand.Subcommands.Add(didRevokeCommand);

        didRevokeCommand.SetAction(parseResult =>
        {
            int id = parseResult.GetValue(revokeIdArgument);
            var result = VerifiableOperations.RevokeDid(id);
            Console.WriteLine(result.Value);

            return 0;
        });

        Command didListCommand = new("list", "List all DID documents.");
        didCommand.Subcommands.Add(didListCommand);

        didListCommand.SetAction(_ =>
        {
            var result = VerifiableOperations.ListDids();
            Console.WriteLine(result.Value);

            return 0;
        });

        Argument<int> viewIdArgument = new("id") { Description = "DID identifier for a document to view." };

        Command didViewCommand = new("view", "View DID document.")
        {
            viewIdArgument
        };
        didCommand.Subcommands.Add(didViewCommand);

        didViewCommand.SetAction(parseResult =>
        {
            int id = parseResult.GetValue(viewIdArgument);
            var result = VerifiableOperations.ViewDid(id);
            Console.WriteLine(result.Value);

            return 0;
        });

        Command infoCommand = new("info", "Print selected platform information.");
        rootCommand.Subcommands.Add(infoCommand);

        Option<bool> jsonOption = new("--json", "-j") { Description = "Output as JSON." };
        Option<string?> outputOption = new("--output", "-o") { Description = "Write output to file." };
        Option<bool> revealOption = new("--reveal") { Description = "Reveal sensitive values (PCR digests). Use with caution." };

        Command infoTpmCommand = new("tpm", "Print trusted platform module (TPM) information.")
        {
            jsonOption,
            outputOption,
            revealOption
        };
        infoCommand.Subcommands.Add(infoTpmCommand);

        infoTpmCommand.SetAction(async parseResult =>
        {
            bool useJson = parseResult.GetValue(jsonOption);
            string? outputPath = parseResult.GetValue(outputOption);
            bool reveal = parseResult.GetValue(revealOption);

            //If output path specified, always use JSON format.
            if(outputPath is not null)
            {
                if(!reveal)
                {
                    Console.WriteLine(ConsoleFormatter.Warning("Warning: Saving full TPM data including PCR values to file."));
                    Console.WriteLine(ConsoleFormatter.Dim("  PCR values can fingerprint your system. Consider if this file will be shared."));
                    Console.WriteLine();
                }

                var saveResult = await VerifiableOperations.SaveTpmInfoToFileAsync(outputPath);

                if(saveResult.IsSuccess)
                {
                    Console.WriteLine($"TPM data saved to: {saveResult.Value}");
                    return 0;
                }

                Console.Error.WriteLine(ConsoleFormatter.Error(saveResult.Error!));
                return 1;
            }

            //Output to stdout.
            if(useJson)
            {
                if(!reveal)
                {
                    Console.Error.WriteLine(ConsoleFormatter.Warning("Warning: JSON output includes full PCR values."));
                    Console.Error.WriteLine(ConsoleFormatter.Dim("  Use --reveal to acknowledge, or pipe to file intentionally."));
                    Console.Error.WriteLine();
                }

                var jsonResult = VerifiableOperations.GetTpmInfoAsJson();

                if(jsonResult.IsSuccess)
                {
                    Console.WriteLine(jsonResult.Value);
                    return 0;
                }

                Console.Error.WriteLine(ConsoleFormatter.Error(jsonResult.Error!));
                return 1;
            }

            //Human-readable format (default).
            var infoResult = VerifiableOperations.GetTpmInfo();

            if(infoResult.IsSuccess)
            {
                TpmInfoFormatter.WriteToConsole(infoResult.Value!, reveal);
                return 0;
            }

            Console.Error.WriteLine(ConsoleFormatter.Error(infoResult.Error!));
            return 1;
        });

        //Event log command - subcommand of tpm.
        Option<int?> pcrFilterOption = new("--pcr", "-p") { Description = "Filter events by PCR index (0-23)." };
        Option<bool> summaryOnlyOption = new("--summary", "-s") { Description = "Show summary only, no individual events." };
        Option<bool> chronologicalOption = new("--chronological", "-c") { Description = "Show events in boot order (oldest first). Default is newest first." };

        Command tpmEventLogCommand = new("eventlog", "Print detailed TCG event log (boot measurements).")
        {
            revealOption,
            pcrFilterOption,
            summaryOnlyOption,
            chronologicalOption
        };
        infoTpmCommand.Subcommands.Add(tpmEventLogCommand);

        tpmEventLogCommand.SetAction(parseResult =>
        {
            bool reveal = parseResult.GetValue(revealOption);
            int? pcrFilter = parseResult.GetValue(pcrFilterOption);
            bool summaryOnly = parseResult.GetValue(summaryOnlyOption);
            bool chronological = parseResult.GetValue(chronologicalOption);

            var log = TcgEventLogFormatter.TryReadEventLog(out string? error);

            if(log is null)
            {
                Console.Error.WriteLine(ConsoleFormatter.Error($"Failed to read event log: {error}"));
                return 1;
            }

            if(summaryOnly)
            {
                TcgEventLogFormatter.WriteSummary(log);
                Console.WriteLine();
                TcgEventLogFormatter.WritePcrSummary(log);
            }
            else
            {
                TcgEventLogFormatter.WriteFull(log, reveal, pcrFilter, chronological);
            }

            return 0;
        });

        var parsed = rootCommand.Parse(args);

        //Handle --no-color before any command runs.
        if(parsed.GetValue(noColorOption))
        {
            ConsoleFormatter.DisableColors();
        }

        return await parsed.InvokeAsync();
    }
}