using Spectre.Console;
using Spectre.Console.Cli;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using Verifiable.Tpm;

namespace Verifiable
{
    public class DidCreateCommand: AsyncCommand<DidCreateCommand.DidSettings>
    {
        public class DidSettings: CommandSettings
        {
            [CommandArgument(0, "<ID>")]
            [Description("Identifier for the new DID document.")]
            public int Id { get; set; }

            [CommandArgument(1, "<Param>")]
            [Description("New DID document parameter.")]
            public string? Param { get; set; }

            [CommandOption("-e|--extraParam <Someparam>")]
            [Description("Some extra parameter.")]
            public string? ExtraParam { get; set; }
        }

        public override Task<int> ExecuteAsync(CommandContext context, DidSettings settings)
        {
            var extraParam = settings.ExtraParam ?? string.Empty;
            AnsiConsole.MarkupLine(
                $"[bold blue]Add DID document =>[/] DidDoc[[{settings.Id}]], " +
                $"param[[{settings.Param}]] " +
                $"extraParam[[{extraParam}]]");

            return Task.FromResult(0);
        }
    }


    public class DidRevokeCommand: AsyncCommand<DidRevokeCommand.Settings>
    {
        public class Settings: CommandSettings
        {
            [CommandArgument(0, "<ID>")]
            [Description("Identifier to revoke a DID document.")]
            public int Id { get; set; }
        }

        public override Task<int> ExecuteAsync(CommandContext context, Settings settings)
        {
            AnsiConsole.MarkupLine($"[bold blue]Revoke DID document =>[/] DidDoc[[{settings.Id}]]");
            return Task.FromResult(0);
        }
    }

    public class DidListCommand: AsyncCommand
    {
        public override Task<int> ExecuteAsync(CommandContext context)
        {
            AnsiConsole.MarkupLine("[bold blue]List all DID documents[/]");
            return Task.FromResult(0);
        }
    }


    public class DidViewCommand: AsyncCommand<DidViewCommand.Settings>
    {
        public class Settings: CommandSettings
        {
            [CommandArgument(0, "<ID>")]
            [Description("DID identifier for a document to view.")]
            public int Id { get; set; }
        }

        public override Task<int> ExecuteAsync(CommandContext context, Settings settings)
        {
            AnsiConsole.MarkupLine($"[bold blue]View DID document =>[/] DidDoc[[{settings.Id}]]");
            return Task.FromResult(0);
        }
    }


    public class InfoTpmCommand: AsyncCommand
    {
        public override async Task<int> ExecuteAsync(CommandContext context)
        {
            bool isTpmPlatformSupported = TpmExtensions.IsTpmPlatformSupported();
            if(!isTpmPlatformSupported)
            {
                AnsiConsole.MarkupLine($"[bold red]Trusted platform module (TPM) information is not supported on {RuntimeInformation.OSDescription}.[/]");
                return 1;
            }

            try
            {
                var tpm = new TpmWrapper();
                var tpmInfo = TpmExtensions.GetAllTpmInfo(tpm.Tpm);

                const string JsonFileName = "tpm_data.json";
                string tpmInfoJson = JsonSerializer.Serialize(tpmInfo);
                using(var createStream = new FileStream(JsonFileName, FileMode.Create, FileAccess.Write))
                {
                    await JsonSerializer.SerializeAsync(createStream, tpmInfo);
                }

                AnsiConsole.MarkupLine($"[bold blue]tpm_data.json created[/]");

                return 0;
            }
            catch(Exception ex)
            {
                //TODO: Fix this.
                AnsiConsole.MarkupLine($"[bold red]Unknown error: {ex}.[/]");
            }

            return 1;

        }
    }


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
            var app = new CommandApp();
            app.Configure(config =>
            {
                config.CaseSensitivity(CaseSensitivity.None);
                config.SetApplicationName("verifiable");
                config.ValidateExamples();

                config.AddBranch("did", did =>
                {
                    did.SetDescription("Create, revoke, list or view DIDs.");

                    did.AddCommand<DidCreateCommand>("create")
                        .WithAlias("new")
                        .WithDescription("Create a new DID document.")
                        .WithExample(new[] { "did", "create", "123", "--extraParam", "someExtra" });

                    did.AddCommand<DidRevokeCommand>("revoke")
                        .WithDescription("Revoke a DID document.")
                        .WithExample(new[] { "did", "revoke", "123" });

                    did.AddCommand<DidListCommand>("list")
                        .WithDescription("List all DID documents.")
                        .WithExample(new[] { "did", "list" });

                    did.AddCommand<DidViewCommand>("view")
                        .WithDescription("View DID document.")
                        .WithExample(new[] { "did", "view", "123" });
                });

                config.AddBranch("info", info =>
                {
                    info.SetDescription("Print selected platform information (only tpm currently)");
                    info.AddCommand<InfoTpmCommand>("tpm")
                        .WithDescription("Print trusted platform module (TPM) information")
                        .WithExample(new[] { "info", "tpm" });
                });
            });

            return await app.RunAsync(args).ConfigureAwait(false);
        }
    }
}
