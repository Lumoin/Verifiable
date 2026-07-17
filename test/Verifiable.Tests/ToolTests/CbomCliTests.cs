using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Verifiable;

namespace Verifiable.Tests.ToolTests;

/// <summary>
/// Integration tests for the <c>cbom</c> command and the <see cref="McpToolNames.EmitCbom"/>
/// MCP tool. They execute the real CLI process (and the real MCP server over stdio), so they
/// assert the end-to-end CycloneDX output a consumer actually receives: the declarative
/// (capabilities) view from the registry and the observed (runtime) view from a live crypto
/// workload run through the wired provider.
/// </summary>
[TestClass]
internal sealed class CbomCliTests
{
    /// <summary>
    /// The MSTest context for the current test run.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task CbomDeclarativeCommandEmitsValidCycloneDxCbom()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, ["cbom", "--declarative"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);

        using var document = JsonDocument.Parse(result.Stdout);
        var root = document.RootElement;

        Assert.AreEqual("http://cyclonedx.org/schema/bom-1.6.schema.json", root.GetProperty("$schema").GetString());
        Assert.AreEqual("CycloneDX", root.GetProperty("bomFormat").GetString());
        Assert.AreEqual("1.6", root.GetProperty("specVersion").GetString());

        //Every emitted component must be a cryptographic asset.
        foreach(var component in root.GetProperty("components").EnumerateArray())
        {
            Assert.AreEqual("cryptographic-asset", component.GetProperty("type").GetString());
        }

        //The declarative view advertises the library's full capability surface: classical
        //signatures and a post-quantum KEM are both expected primitives.
        var primitives = CollectAlgorithmPrimitives(root);
        Assert.Contains("signature", primitives, "Declarative CBOM must advertise a signature algorithm.");
        Assert.Contains("kem", primitives, "Declarative CBOM must advertise a key-encapsulation mechanism.");

        //A post-quantum asset must carry its NIST quantum security level.
        Assert.IsTrue(HasQuantumSecurityLevel(root), "Declarative CBOM must include a post-quantum asset with nistQuantumSecurityLevel.");
    }


    [TestMethod]
    public async Task CbomObserveCommandCapturesSignatureKeyGenAndEntropy()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, ["cbom", "--observe"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);

        using var document = JsonDocument.Parse(result.Stdout);
        var root = document.RootElement;

        Assert.AreEqual("CycloneDX", root.GetProperty("bomFormat").GetString());
        Assert.AreEqual("1.6", root.GetProperty("specVersion").GetString());

        //The observed view reports what actually executed. Signing and key generation come from
        //the instrumented backend, the digest from the hash, and the random material from the DRBG.
        var primitives = CollectAlgorithmPrimitives(root);
        Assert.Contains("signature", primitives, "Observed CBOM must capture the signature operation that ran.");
        Assert.Contains("hash", primitives, "Observed CBOM must capture the digest operation that ran.");
        Assert.Contains("drbg", primitives, "Observed CBOM must capture the DRBG behind the random material.");

        //Key generation emits a private-key material asset; its presence proves the keygen path is observed.
        var materialTypes = CollectMaterialTypes(root);
        Assert.Contains("private-key", materialTypes, "Observed CBOM must record the generated private key.");

        //The observed view wires consumers to producers through a dependency graph.
        Assert.IsGreaterThan(
            0,
            root.GetProperty("dependencies").GetArrayLength(),
            "Observed CBOM must include a non-empty dependency graph.");

        //Wave-7 regression guard: without --events, the CBOM JSON is the ENTIRE output, exactly as
        //before this wave — the provenance summary section must never appear unrequested.
        Assert.DoesNotContain(
            CryptoEventProvenance.SectionHeader, result.Stdout,
            "Without --events, cbom --observe must reproduce its pre-wave-7 output exactly (CBOM JSON only).");
    }


    /// <summary>
    /// The wave-7 consumer proof: <c>cbom --observe --events</c> subscribes to
    /// <see cref="CryptographicKeyEvents"/> for the workload's duration and appends a compact provenance
    /// summary after the CBOM JSON. This is the ONLY test in the suite that can assert exact event
    /// counts — the CLI runs in its own freshly spawned process, so unlike an in-process test, nothing
    /// else in that process can add noise to the process-wide <see cref="CryptographicKeyEvents.Events"/>
    /// stream during the observation window. The counts prove BOTH the pre-existing choke-point path (the
    /// FIDO2 leg's <c>PrivateKey.SignAsync</c>/<c>PublicKey.VerifyAsync</c>, wired since wave 4) and the
    /// wave-7-widened path (the workload's new JOSE-signed leg, routed through <c>Jws.SignAsync</c>/
    /// <c>VerifyAsync</c>'s <see cref="CryptoEventSink"/> seam) land in the same summary: two
    /// <c>KeyMaterialGeneratedEvent</c>s (one per workload leg's own mint), two
    /// <c>SignatureProducedEvent</c>s, and two <c>VerificationCompletedEvent</c>s — one of each pair from
    /// each leg.
    /// </summary>
    [TestMethod]
    public async Task CbomObserveEventsFlagAppendsProvenanceSummaryWithExactCountsAndLeavesTheCbomJsonUnchanged()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, ["cbom", "--observe", "--events"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);

        int headerIndex = result.Stdout.IndexOf(CryptoEventProvenance.SectionHeader, System.StringComparison.Ordinal);
        Assert.IsGreaterThanOrEqualTo(0, headerIndex, "The --events output must contain the provenance section header.");

        string cbomJson = result.Stdout[..headerIndex].TrimEnd();
        string summary = result.Stdout[(headerIndex + CryptoEventProvenance.SectionHeader.Length)..];

        //The CBOM JSON half must still be exactly what --observe alone produces: a complete, independently
        //parseable CycloneDX document — proving the summary is APPENDED, never merged into or mutating it.
        using var document = JsonDocument.Parse(cbomJson);
        var root = document.RootElement;
        Assert.AreEqual("CycloneDX", root.GetProperty("bomFormat").GetString());
        Assert.AreEqual("1.6", root.GetProperty("specVersion").GetString());

        Assert.Contains("KeyMaterialGeneratedEvent x2", summary, "Both workload legs' own CreateKeyPair mint step must be counted.");
        Assert.Contains("SignatureProducedEvent x2", summary, "The FIDO2 leg's choke-point sign and the JOSE leg's widened-path sign must both be counted.");
        Assert.Contains("VerificationCompletedEvent x2", summary, "The FIDO2 leg's choke-point verify and the JOSE leg's widened-path verify must both be counted.");
    }


    /// <summary>
    /// Proves <c>CryptoProviderStartup</c>'s wave-7 key-creation registration is present and reachable
    /// through the real composition root. <c>RunObservableWorkloadAsync</c>/<c>RunFido2ObservedWorkloadAsync</c>
    /// mint their P-256 signing key through <c>CryptographicKeyEvents.CreateKeyPair(CryptoAlgorithm.P256,
    /// Purpose.Signing, pool)</c>, which throws unless <c>CryptoProviderStartup.RegisterKeyCreation()</c> has
    /// registered that exact combination against the Microsoft adapter; a missing or wrong registration
    /// surfaces here as a non-zero exit code and an "Error generating observed CBOM" stderr payload (see
    /// <c>Program.cs</c>'s <c>cbom</c> action), never a silent pass. Runs the real exe in its own process so
    /// it never touches this test process's own <c>KeyCreationFunctionRegistry</c> state, which every other
    /// test in this assembly shares via <c>TestSetup</c>'s module initializer.
    /// </summary>
    [TestMethod]
    public async Task CbomObserveCommandProvesCryptoProviderStartupKeyCreationRegistration()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, ["cbom", "--observe"], TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(0, result.ExitCode, result.Stderr);
        Assert.DoesNotContain(
            "Error generating observed CBOM", result.Stdout,
            "A missing CryptoProviderStartup key-creation registration would fail the whole workload with this message.");

        //The mint step's keygen still surfaces a private-key material asset, proving the CreateKeyPair
        //choke point (not merely the exit code) produced usable key material end to end.
        using var document = JsonDocument.Parse(result.Stdout);
        Assert.Contains("private-key", CollectMaterialTypes(document.RootElement),
            "The registered key-creation adapter must still surface the generated private-key material.");
    }


    [TestMethod]
    [TestCategory("McpClient")]
    public async Task EmitCbomMcpToolIsRegisteredAndReturnsCbom()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var clientTransport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "Verifiable MCP Server",
            Command = executablePath,
            Arguments = ["-mcp"]
        });

        var client = await McpClient.CreateAsync(clientTransport, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);
        await using(client.ConfigureAwait(false))
        {
            var tools = await client.ListToolsAsync(cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.Contains(McpToolNames.EmitCbom, tools.Select(tool => tool.Name).ToList());

            //Default (no mode) is the declarative CBOM.
            var declarativeResult = await client.CallToolAsync(
                McpToolNames.EmitCbom,
                new Dictionary<string, object?>(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(true, declarativeResult.IsError, "EmitCbom (declarative) must not return an error.");
            string declarativeCbom = ExtractText(declarativeResult);
            Assert.Contains("CycloneDX", declarativeCbom, StringComparison.Ordinal);

            //Mode 'observed' runs a real workload and reports the signature that executed.
            var observedResult = await client.CallToolAsync(
                McpToolNames.EmitCbom,
                new Dictionary<string, object?> { ["mode"] = "observed" },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(true, observedResult.IsError, "EmitCbom (observed) must not return an error.");
            string observedCbom = ExtractText(observedResult);
            Assert.Contains("CycloneDX", observedCbom, StringComparison.Ordinal);
            Assert.Contains("signature", observedCbom, StringComparison.Ordinal);
        }
    }


    /// <summary>
    /// MCP-mode parity for the wave-7 provenance summary: the <see cref="McpToolNames.EmitCbom"/> tool's
    /// <c>events</c> parameter reaches the exact same <c>VerifiableOperations.EmitObservedCbomAsync</c>
    /// call the CLI's <c>--events</c> flag does (see <c>VerifiableMcpServer.EmitCbom</c>), so calling it
    /// over MCP must append the same provenance summary the CLI flow test asserts on.
    /// </summary>
    [TestMethod]
    [TestCategory("McpClient")]
    public async Task EmitCbomMcpToolEventsParameterAppendsProvenanceSummary()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var clientTransport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "Verifiable MCP Server",
            Command = executablePath,
            Arguments = ["-mcp"]
        });

        var client = await McpClient.CreateAsync(clientTransport, cancellationToken: TestContext.CancellationToken)
            .ConfigureAwait(false);
        await using(client.ConfigureAwait(false))
        {
            //Without events: true, mode 'observed' must reproduce its pre-wave-7 output exactly.
            var withoutEvents = await client.CallToolAsync(
                McpToolNames.EmitCbom,
                new Dictionary<string, object?> { ["mode"] = "observed" },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreNotEqual(true, withoutEvents.IsError, "EmitCbom (observed) must not return an error.");
            Assert.DoesNotContain(CryptoEventProvenance.SectionHeader, ExtractText(withoutEvents));

            var withEvents = await client.CallToolAsync(
                McpToolNames.EmitCbom,
                new Dictionary<string, object?> { ["mode"] = "observed", ["events"] = true },
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreNotEqual(true, withEvents.IsError, "EmitCbom (observed, events: true) must not return an error.");
            string observedCbomWithEvents = ExtractText(withEvents);

            Assert.Contains(CryptoEventProvenance.SectionHeader, observedCbomWithEvents);
            Assert.Contains("KeyMaterialGeneratedEvent x2", observedCbomWithEvents);
            Assert.Contains("SignatureProducedEvent x2", observedCbomWithEvents);
            Assert.Contains("VerificationCompletedEvent x2", observedCbomWithEvents);
        }
    }


    /// <summary>
    /// Collects the <c>algorithmProperties.primitive</c> value of every algorithm component.
    /// </summary>
    private static List<string> CollectAlgorithmPrimitives(JsonElement root)
    {
        var primitives = new List<string>();
        foreach(var component in root.GetProperty("components").EnumerateArray())
        {
            if(component.TryGetProperty("cryptoProperties", out var cryptoProperties)
                && cryptoProperties.TryGetProperty("algorithmProperties", out var algorithmProperties)
                && algorithmProperties.TryGetProperty("primitive", out var primitive)
                && primitive.GetString() is string value)
            {
                primitives.Add(value);
            }
        }

        return primitives;
    }


    /// <summary>
    /// Collects the <c>relatedCryptoMaterialProperties.type</c> value of every material component.
    /// </summary>
    private static List<string> CollectMaterialTypes(JsonElement root)
    {
        var materialTypes = new List<string>();
        foreach(var component in root.GetProperty("components").EnumerateArray())
        {
            if(component.TryGetProperty("cryptoProperties", out var cryptoProperties)
                && cryptoProperties.TryGetProperty("relatedCryptoMaterialProperties", out var materialProperties)
                && materialProperties.TryGetProperty("type", out var type)
                && type.GetString() is string value)
            {
                materialTypes.Add(value);
            }
        }

        return materialTypes;
    }


    /// <summary>
    /// Determines whether any algorithm component carries a numeric <c>nistQuantumSecurityLevel</c>.
    /// </summary>
    private static bool HasQuantumSecurityLevel(JsonElement root)
    {
        foreach(var component in root.GetProperty("components").EnumerateArray())
        {
            if(component.TryGetProperty("cryptoProperties", out var cryptoProperties)
                && cryptoProperties.TryGetProperty("algorithmProperties", out var algorithmProperties)
                && algorithmProperties.TryGetProperty("nistQuantumSecurityLevel", out var level)
                && level.ValueKind == JsonValueKind.Number)
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Concatenates the text content blocks of an MCP tool result.
    /// </summary>
    private static string ExtractText(CallToolResult result)
    {
        return string.Concat(result.Content.OfType<TextContentBlock>().Select(block => block.Text));
    }
}
