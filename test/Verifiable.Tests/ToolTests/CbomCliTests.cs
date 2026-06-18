using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

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
