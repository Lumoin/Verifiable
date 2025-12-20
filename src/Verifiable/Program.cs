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

        Command infoCommand = new("info", "Print selected platform information (only tpm currently).");
        rootCommand.Subcommands.Add(infoCommand);

        Command infoTpmCommand = new("tpm", "Print trusted platform module (TPM) information.");
        infoCommand.Subcommands.Add(infoTpmCommand);

        infoTpmCommand.SetAction(async parseResult =>
        {
            var result = await VerifiableOperations.SaveTpmInfoToFileAsync();

            if(result.IsSuccess)
            {
                Console.WriteLine($"TPM data saved to: {result.Value}");

                return 0;
            }

            Console.Error.WriteLine(result.Error);

            return 1;
        });

        return await rootCommand.Parse(args).InvokeAsync();
    }
}