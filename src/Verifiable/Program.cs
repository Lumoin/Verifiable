using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.CommandLine;
using System.IO;
using System.Threading.Tasks;
using Verifiable.Core;

namespace Verifiable;

/// <summary>
/// A console program for DID and VC documents.
/// </summary>
internal static class Program
{
    /// <summary>
    /// An entry point to a console program for DID and VC documents.
    /// </summary>
    /// <param name="args">The arguments to the program.</param>
    /// <returns>The exit code from the program.</returns>
    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if(args.Length == 1 && args[0] == "-mcp")
        {
            return await RunMcpServerAsync(args).ConfigureAwait(false);
        }

        return await RunCliAsync(args).ConfigureAwait(false);
    }

    private static async Task<int> RunMcpServerAsync(string[] args)
    {
        //Wire the cryptographic provider once for every provider-dependent MCP tool — mirrors
        //RunCliAsync's own call below; previously missing here (a shipped gap the FIDO2 verbs need
        //closed since VerifyFido2Registration/VerifyFido2Assertion need the registry populated).
        CryptoProviderStartup.EnsureRegistered();

        var builder = Host.CreateApplicationBuilder(args);

        builder.Services.AddMcpServer()
            .WithStdioServerTransport()
            .WithTools<VerifiableMcpServer>();

        builder.Logging.AddConsole(options =>
        {
            options.LogToStandardErrorThreshold = LogLevel.Trace;
        });

        await builder.Build().RunAsync().ConfigureAwait(false);

        return 0;
    }

    private static async Task<int> RunCliAsync(string[] args)
    {
        //Wire the cryptographic provider once for every provider-dependent command.
        //This is the reusable seam future did/vc commands also build on.
        CryptoProviderStartup.EnsureRegistered();

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

                var saveResult = await VerifiableOperations.SaveTpmInfoToFileAsync(outputPath).ConfigureAwait(false);

                if(saveResult.IsSuccess)
                {
                    Console.WriteLine($"TPM data saved to: {saveResult.Value}");
                    return 0;
                }

                await Console.Error.WriteLineAsync(ConsoleFormatter.Error(saveResult.Error!)).ConfigureAwait(false);
                return 1;
            }

            //Output to stdout.
            if(useJson)
            {
                if(!reveal)
                {
                    await Console.Error.WriteLineAsync(ConsoleFormatter.Warning("Warning: JSON output includes full PCR values.")).ConfigureAwait(false);
                    await Console.Error.WriteLineAsync(ConsoleFormatter.Dim("  Use --reveal to acknowledge, or pipe to file intentionally.")).ConfigureAwait(false);
                    await Console.Error.WriteLineAsync().ConfigureAwait(false);
                }

                var jsonResult = await VerifiableOperations.GetTpmInfoAsJsonAsync().ConfigureAwait(false);

                if(jsonResult.IsSuccess)
                {
                    Console.WriteLine(jsonResult.Value);
                    return 0;
                }

                await Console.Error.WriteLineAsync(ConsoleFormatter.Error(jsonResult.Error!)).ConfigureAwait(false);
                return 1;
            }

            //Human-readable format (default).
            var infoResult = await VerifiableOperations.GetTpmInfoAsync().ConfigureAwait(false);

            if(infoResult.IsSuccess)
            {
                TpmInfoFormatter.WriteToConsole(infoResult.Value!, reveal);
                return 0;
            }

            await Console.Error.WriteLineAsync(ConsoleFormatter.Error(infoResult.Error!)).ConfigureAwait(false);
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

        //CBOM command: emit a CycloneDX 1.6 Cryptographic Bill of Materials.
        Option<bool> declarativeOption = new("--declarative")
        {
            Description = "Emit the declarative (capabilities) CBOM from the registry. This is the default."
        };
        Option<bool> observeOption = new("--observe")
        {
            Description = "Run a real crypto workload through the wired provider and emit the observed (runtime) CBOM."
        };
        Option<string?> cbomOutputOption = new("--output", "-o") { Description = "Write the CBOM JSON to a file." };
        Option<bool> cbomEventsOption = new("--events")
        {
            Description = "With --observe, subscribe to the CryptoEvent stream for the workload's duration and " +
                "append a compact provenance summary (counts by event type, algorithm, and backend) after the " +
                "CBOM JSON. The CBOM JSON itself is unchanged. Has no effect with --declarative, which performs " +
                "no cryptographic operation to observe."
        };

        Command cbomCommand = new("cbom", "Emit a CycloneDX cryptographic bill of materials (CBOM).")
        {
            declarativeOption,
            observeOption,
            cbomEventsOption,
            cbomOutputOption
        };
        rootCommand.Subcommands.Add(cbomCommand);

        cbomCommand.SetAction(async parseResult =>
        {
            bool observe = parseResult.GetValue(observeOption);
            bool includeEvents = parseResult.GetValue(cbomEventsOption);
            string? outputPath = parseResult.GetValue(cbomOutputOption);

            Result<string, string> result = observe
                ? await VerifiableOperations.EmitObservedCbomAsync(includeEventProvenance: includeEvents).ConfigureAwait(false)
                : VerifiableOperations.EmitDeclarativeCbom();

            if(!result.IsSuccess)
            {
                await Console.Error.WriteLineAsync(ConsoleFormatter.Error(result.Error!)).ConfigureAwait(false);
                return 1;
            }

            if(outputPath is not null)
            {
                await File.WriteAllTextAsync(outputPath, result.Value).ConfigureAwait(false);
                Console.WriteLine($"CBOM written to: {Path.GetFullPath(outputPath)}");
                return 0;
            }

            Console.WriteLine(result.Value);
            return 0;
        });

        //FIDO2/WebAuthn commands: registration/assertion verification and challenge generation.
        Command fido2Command = new("fido2", "Verify WebAuthn registration/assertion ceremonies and create challenges.");
        rootCommand.Subcommands.Add(fido2Command);

        Argument<string> attestationObjectArgument = new("attestation-object") { Description = "File path to the raw attestationObject CBOR bytes." };
        Argument<string> registrationClientDataArgument = new("client-data") { Description = "File path to the raw clientDataJSON bytes." };
        Option<string> registrationRpIdOption = new("--rp-id") { Description = "The relying party ID.", Required = true };
        Option<string> registrationOriginOption = new("--origin") { Description = "The accepted origin.", Required = true };
        Option<string> registrationChallengeOption = new("--challenge") { Description = "The base64url-encoded challenge exactly as issued to the client.", Required = true };
        Option<string[]> trustAnchorOption = new("--trust-anchor")
        {
            Description = "Repeatable PEM/DER attestation root certificate file path. Mutually exclusive with --mds-blob/--mds-root."
        };
        Option<string?> mdsBlobOption = new("--mds-blob") { Description = "File path to a compact-JWS FIDO Metadata Service BLOB." };
        Option<string?> mdsRootOption = new("--mds-root") { Description = "File path to the MDS root certificate --mds-blob chains to." };
        Option<string?> registrationOutputOption = new("--output", "-o") { Description = "Write the credential record JSON to a file." };
        Option<string?> registrationUserVerificationOption = new("--user-verification")
        {
            Description = "The relying party's user-verification policy: required, preferred, or discouraged. Defaults to preferred."
        };
        Option<string?> registrationAuthenticatorAttachmentOption = new("--authenticator-attachment")
        {
            Description = "The client-reported authenticatorAttachment value to store on the credential record: platform or cross-platform."
        };
        Option<bool> registrationRequireTeeEnforcedAuthorizationsOption = new("--require-tee-enforced-authorizations")
        {
            Description = "For an android-key attestation, require the origin/purpose authorizations to be satisfied by the teeEnforced list alone (rejects a software-only key). Defaults to false (union of teeEnforced and softwareEnforced)."
        };

        Command verifyRegistrationCommand = new("verify-registration", "Verify a WebAuthn registration ceremony's attestation object.")
        {
            attestationObjectArgument,
            registrationClientDataArgument,
            registrationRpIdOption,
            registrationOriginOption,
            registrationChallengeOption,
            trustAnchorOption,
            mdsBlobOption,
            mdsRootOption,
            registrationOutputOption,
            registrationUserVerificationOption,
            registrationAuthenticatorAttachmentOption,
            registrationRequireTeeEnforcedAuthorizationsOption
        };
        fido2Command.Subcommands.Add(verifyRegistrationCommand);

        verifyRegistrationCommand.SetAction(async parseResult =>
        {
            string attestationObjectPath = parseResult.GetValue(attestationObjectArgument)!;
            string clientDataPath = parseResult.GetValue(registrationClientDataArgument)!;
            string rpId = parseResult.GetValue(registrationRpIdOption)!;
            string origin = parseResult.GetValue(registrationOriginOption)!;
            string challenge = parseResult.GetValue(registrationChallengeOption)!;
            string[]? trustAnchorPaths = parseResult.GetValue(trustAnchorOption);
            string? mdsBlobPath = parseResult.GetValue(mdsBlobOption);
            string? mdsRootPath = parseResult.GetValue(mdsRootOption);
            string? outputPath = parseResult.GetValue(registrationOutputOption);
            string? userVerification = parseResult.GetValue(registrationUserVerificationOption);
            string? authenticatorAttachment = parseResult.GetValue(registrationAuthenticatorAttachmentOption);
            bool requireTeeEnforcedAuthorizations = parseResult.GetValue(registrationRequireTeeEnforcedAuthorizationsOption);

            var result = await VerifiableOperations.VerifyFido2RegistrationAsync(
                attestationObjectPath, clientDataPath, rpId, origin, challenge, trustAnchorPaths, mdsBlobPath, mdsRootPath,
                requireTeeEnforcedAuthorizations: requireTeeEnforcedAuthorizations,
                userVerification: userVerification, authenticatorAttachment: authenticatorAttachment)
                .ConfigureAwait(false);

            if(!result.IsSuccess)
            {
                await Console.Error.WriteLineAsync(ConsoleFormatter.Error(result.Error!)).ConfigureAwait(false);
                return 1;
            }

            if(outputPath is not null)
            {
                await File.WriteAllTextAsync(outputPath, result.Value).ConfigureAwait(false);
                Console.WriteLine($"Credential record written to: {Path.GetFullPath(outputPath)}");
                return 0;
            }

            Console.WriteLine(result.Value);
            return 0;
        });

        Argument<string> credentialRecordArgument = new("credential-record") { Description = "File path to the credential record JSON document produced by 'verify-registration'." };
        Argument<string> assertionAuthenticatorDataArgument = new("authenticator-data") { Description = "File path to the raw authData bytes (response.authenticatorData)." };
        Argument<string> assertionSignatureArgument = new("signature") { Description = "File path to the raw assertion signature bytes (response.signature)." };
        Argument<string> assertionClientDataArgument = new("client-data") { Description = "File path to the raw clientDataJSON bytes." };
        Option<string> assertionRpIdOption = new("--rp-id") { Description = "The relying party ID.", Required = true };
        Option<string> assertionOriginOption = new("--origin") { Description = "The accepted origin.", Required = true };
        Option<string> assertionChallengeOption = new("--challenge") { Description = "The base64url-encoded challenge exactly as issued to the client.", Required = true };
        Option<uint> storedSignCountOption = new("--stored-sign-count") { Description = "The signature counter value stored for this credential from the previous ceremony. Defaults to 0." };
        Option<string?> assertionUserVerificationOption = new("--user-verification")
        {
            Description = "The relying party's user-verification policy: required, preferred, or discouraged. Defaults to preferred."
        };
        Option<string?> userHandleOption = new("--user-handle") { Description = "Optional file path to the raw response.userHandle bytes." };

        Command verifyAssertionCommand = new("verify-assertion", "Verify a WebAuthn authentication ceremony's assertion.")
        {
            credentialRecordArgument,
            assertionAuthenticatorDataArgument,
            assertionSignatureArgument,
            assertionClientDataArgument,
            assertionRpIdOption,
            assertionOriginOption,
            assertionChallengeOption,
            storedSignCountOption,
            assertionUserVerificationOption,
            userHandleOption
        };
        fido2Command.Subcommands.Add(verifyAssertionCommand);

        verifyAssertionCommand.SetAction(async parseResult =>
        {
            string credentialRecordPath = parseResult.GetValue(credentialRecordArgument)!;
            string authenticatorDataPath = parseResult.GetValue(assertionAuthenticatorDataArgument)!;
            string signaturePath = parseResult.GetValue(assertionSignatureArgument)!;
            string clientDataPath = parseResult.GetValue(assertionClientDataArgument)!;
            string rpId = parseResult.GetValue(assertionRpIdOption)!;
            string origin = parseResult.GetValue(assertionOriginOption)!;
            string challenge = parseResult.GetValue(assertionChallengeOption)!;
            uint storedSignCount = parseResult.GetValue(storedSignCountOption);
            string? userVerification = parseResult.GetValue(assertionUserVerificationOption);
            string? userHandlePath = parseResult.GetValue(userHandleOption);

            var result = await VerifiableOperations.VerifyFido2AssertionAsync(
                credentialRecordPath, authenticatorDataPath, signaturePath, clientDataPath, rpId, origin, challenge,
                storedSignCount, userVerification, userHandlePath)
                .ConfigureAwait(false);

            if(!result.IsSuccess)
            {
                await Console.Error.WriteLineAsync(ConsoleFormatter.Error(result.Error!)).ConfigureAwait(false);
                return 1;
            }

            Console.WriteLine(result.Value);
            return 0;
        });

        Option<int?> challengeLengthOption = new("--length") { Description = "The challenge length in bytes. Defaults to 32; enforces a floor of 16." };
        Option<string?> challengeOutputOption = new("--output", "-o") { Description = "Write the base64url challenge to a file." };

        Command challengeCommand = new("challenge", "Create a WebAuthn cryptographic challenge.")
        {
            challengeLengthOption,
            challengeOutputOption
        };
        fido2Command.Subcommands.Add(challengeCommand);

        challengeCommand.SetAction(async parseResult =>
        {
            int? byteLength = parseResult.GetValue(challengeLengthOption);
            string? outputPath = parseResult.GetValue(challengeOutputOption);

            var result = VerifiableOperations.CreateFido2Challenge(byteLength);

            if(!result.IsSuccess)
            {
                await Console.Error.WriteLineAsync(ConsoleFormatter.Error(result.Error!)).ConfigureAwait(false);
                return 1;
            }

            if(outputPath is not null)
            {
                await File.WriteAllTextAsync(outputPath, result.Value).ConfigureAwait(false);
                Console.WriteLine($"Challenge written to: {Path.GetFullPath(outputPath)}");
                return 0;
            }

            Console.WriteLine(result.Value);
            return 0;
        });

        var parsed = rootCommand.Parse(args);

        //Handle --no-color before any command runs.
        if(parsed.GetValue(noColorOption))
        {
            ConsoleFormatter.DisableColors();
        }

        return await parsed.InvokeAsync().ConfigureAwait(false);
    }
}
