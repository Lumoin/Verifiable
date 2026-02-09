using ModelContextProtocol.Client;
using System.Globalization;
using System.Text.Json;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;

namespace Verifiable.Tests.ToolTests;

/// <summary>
/// Tests for the shared operations and MCP server functionality.
/// </summary>
[TestClass]
internal sealed class McpServerTests
{
    /// <summary>
    /// Gets or sets the context information for the current test run, including test metadata
    /// and utilities for logging and result tracking.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    [SkipIfNoTpm]
    public void CheckTpmSupportMessageReturnsValidResponse()
    {
        string result = VerifiableOperations.CheckTpmSupportMessage();

        Assert.IsNotNull(result);
        Assert.IsGreaterThan(0, result.Length);

        //Message should contain platform info and indicate support status.
        Assert.Contains("platform", result, StringComparison.OrdinalIgnoreCase);

        //Should indicate either "supported and available" or "not supported".
        bool indicatesAvailable = result.Contains("supported and available", StringComparison.OrdinalIgnoreCase);
        bool indicatesNotAvailable = result.Contains("not supported", StringComparison.OrdinalIgnoreCase) ||
                                     result.Contains("not available", StringComparison.OrdinalIgnoreCase);

        Assert.IsTrue(indicatesAvailable || indicatesNotAvailable, "Message should clearly indicate TPM availability status.");
    }


    [TestMethod]
    public void CreateDidValidParametersReturnsSuccess()
    {
        int id = 123;
        string param = "testParam";
        string? extraParam = "extraValue";

        var result = VerifiableOperations.CreateDid(id, param, extraParam);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
        Assert.Contains("123", result.Value, StringComparison.Ordinal);
        Assert.Contains("testParam", result.Value, StringComparison.Ordinal);
        Assert.Contains("extraValue", result.Value, StringComparison.Ordinal);
    }


    [TestMethod]
    public void CreateDidWithoutExtraParamReturnsSuccess()
    {
        int id = 456;
        string param = "myParam";

        var result = VerifiableOperations.CreateDid(id, param, null);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
        Assert.Contains("456", result.Value, StringComparison.Ordinal);
        Assert.Contains("myParam", result.Value, StringComparison.Ordinal);
        Assert.DoesNotContain("Extra parameter:", result.Value, StringComparison.Ordinal);
    }


    [TestMethod]
    public void RevokeDidValidIdReturnsSuccess()
    {
        int id = 789;

        var result = VerifiableOperations.RevokeDid(id);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
        Assert.Contains("789", result.Value, StringComparison.Ordinal);
        Assert.Contains("Revoked", result.Value, StringComparison.OrdinalIgnoreCase);
    }


    [TestMethod]
    public void ListDidsReturnsSuccess()
    {
        var result = VerifiableOperations.ListDids();

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
    }


    [TestMethod]
    public void ViewDidValidIdReturnsSuccess()
    {
        int id = 42;

        var result = VerifiableOperations.ViewDid(id);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
        Assert.Contains("42", result.Value, StringComparison.Ordinal);
    }


    [TestMethod]
    [SkipIfNoTpm]
    public void GetTpmInfoAsJsonReturnsValidJsonOrError()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive(TestInfrastructureConstants.NoTpmDeviceAvailableMessage);
        }

        var result = VerifiableOperations.GetTpmInfoAsJson();

        if(result.IsSuccess)
        {
            using var doc = JsonDocument.Parse(result.Value!);
            Assert.AreEqual(JsonValueKind.Object, doc.RootElement.ValueKind);
        }
        else
        {
            Assert.IsNotNull(result.Error);
            bool hasExpectedError = result.Error.Contains("not supported", StringComparison.Ordinal) ||
                                    result.Error.Contains("Error", StringComparison.Ordinal);
            Assert.IsTrue(hasExpectedError, "Error message should indicate not supported or error.");
        }
    }


    [TestMethod]
    [SkipIfNoTpm]
    public async Task SaveTpmInfoToFileAsyncReturnsExpectedResult()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive(TestInfrastructureConstants.NoTpmDeviceAvailableMessage);
        }

        string testFilePath = Path.Combine(Path.GetTempPath(), $"test_tpm_{Guid.NewGuid()}.json");
        try
        {
            var result = await VerifiableOperations.SaveTpmInfoToFileAsync(testFilePath)
                .ConfigureAwait(false);

            if(result.IsSuccess)
            {
                Assert.IsNotNull(result.Value);
                Assert.IsTrue(File.Exists(testFilePath), "File should exist when save succeeds.");
            }
            else
            {
                Assert.IsNotNull(result.Error);
                bool hasExpectedError = result.Error.Contains("not supported", StringComparison.Ordinal) ||
                                        result.Error.Contains("Error", StringComparison.Ordinal);
                Assert.IsTrue(hasExpectedError, "Error message should be clear.");
            }
        }
        finally
        {
            if(File.Exists(testFilePath))
            {
                File.Delete(testFilePath);
            }
        }
    }


    [TestMethod]
    [SkipIfNoTpm]
    public async Task SaveTpmInfoToFileAsyncNullPathUsesDefaultFileName()
    {
        if(!TpmDevice.IsAvailable)
        {
            Assert.Inconclusive(TestInfrastructureConstants.NoTpmDeviceAvailableMessage);
        }

        var result = await VerifiableOperations.SaveTpmInfoToFileAsync(null)
            .ConfigureAwait(false);

        if(result.IsSuccess)
        {
            Assert.IsNotNull(result.Value);
            Assert.Contains("tpm_data.json", result.Value, StringComparison.Ordinal);
        }
    }


    [TestMethod]
    public void CreateDidBoundaryValuesHandlesCorrectly()
    {
        var maxResult = VerifiableOperations.CreateDid(int.MaxValue, "param", null);
        Assert.IsTrue(maxResult.IsSuccess);
        Assert.Contains(int.MaxValue.ToString(CultureInfo.InvariantCulture), maxResult.Value!, StringComparison.Ordinal);

        var minResult = VerifiableOperations.CreateDid(int.MinValue, "param", null);
        Assert.IsTrue(minResult.IsSuccess);
        Assert.Contains(int.MinValue.ToString(CultureInfo.InvariantCulture), minResult.Value!, StringComparison.Ordinal);

        var zeroResult = VerifiableOperations.CreateDid(0, "param", null);
        Assert.IsTrue(zeroResult.IsSuccess);
        Assert.Contains("0", zeroResult.Value!, StringComparison.Ordinal);
    }


    [TestMethod]
    public void CreateDidUnicodeParametersHandlesCorrectly()
    {
        string unicodeParam = "日本語_émojis_🔐🔑_中文";
        string unicodeExtra = "مرحبا_שלום_Привет";

        var result = VerifiableOperations.CreateDid(1, unicodeParam, unicodeExtra);

        Assert.IsTrue(result.IsSuccess);
        Assert.Contains(unicodeParam, result.Value!, StringComparison.Ordinal);
        Assert.Contains(unicodeExtra, result.Value!, StringComparison.Ordinal);
    }


    [TestMethod]
    public void CreateDidEmptyStringParameterHandlesCorrectly()
    {
        var result = VerifiableOperations.CreateDid(1, "", "");

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
    }


    [TestMethod]
    public void CreateDidVeryLongParameterHandlesCorrectly()
    {
        string longParam = new('x', 10000);

        var result = VerifiableOperations.CreateDid(1, longParam, null);

        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.Value);
        Assert.Contains(longParam, result.Value, StringComparison.Ordinal);
    }


    /// <summary>
    /// Tests that the MCP server process starts correctly with -mcp argument via stdio.
    /// </summary>
    [TestMethod]
    public async Task McpServerStartsSuccessfullyViaStdio()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");
        }

        using var process = VerifiableCliTestHelpers.CreateMcpServerProcess(executablePath);

        try
        {
            process.Start();

            string initializeJson = JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-11-25",
                    capabilities = new { },
                    clientInfo = new { name = "test-client", version = "1.0.0" }
                }
            });

            await SendMessageAsync(process, initializeJson, TestContext.CancellationToken)
                .ConfigureAwait(false);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));

            string response = await ReadResponseByIdAsync(process, 1, cts.Token)
                .ConfigureAwait(false);

            using var responseDoc = JsonDocument.Parse(response);
            var root = responseDoc.RootElement;

            Assert.IsTrue(root.TryGetProperty("jsonrpc", out var jsonrpc));
            Assert.AreEqual("2.0", jsonrpc.GetString());

            Assert.IsTrue(root.TryGetProperty("id", out var id));
            Assert.AreEqual(1, id.GetInt32());

            Assert.IsTrue(root.TryGetProperty("result", out _), "Response should have a result property.");
        }
        finally
        {
            await VerifiableCliTestHelpers.EnsureProcessTerminatedAsync(process, TestContext.CancellationToken)
                .ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Tests MCP server lists available tools via stdio.
    /// </summary>
    [TestMethod]
    public async Task McpServerListsToolsViaStdio()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found.");
        }

        using var process = VerifiableCliTestHelpers.CreateMcpServerProcess(executablePath);

        try
        {
            process.Start();

            //Send initialize request.
            string initRequest = JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-11-25",
                    capabilities = new { },
                    clientInfo = new { name = "test", version = "1.0" }
                }
            });

            await SendMessageAsync(process, initRequest, TestContext.CancellationToken)
                .ConfigureAwait(false);

            using var cts1 = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            cts1.CancelAfter(TimeSpan.FromSeconds(5));
            await ReadResponseByIdAsync(process, 1, cts1.Token)
                .ConfigureAwait(false);

            //Send initialized notification.
            string initializedNotification = JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                method = "notifications/initialized"
            });

            await SendMessageAsync(process, initializedNotification, TestContext.CancellationToken)
                .ConfigureAwait(false);

            //Send tools/list request.
            string toolsRequest = JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                id = 2,
                method = "tools/list"
            });

            await SendMessageAsync(process, toolsRequest, TestContext.CancellationToken)
                .ConfigureAwait(false);

            using var cts2 = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            cts2.CancelAfter(TimeSpan.FromSeconds(5));
            string response = await ReadResponseByIdAsync(process, 2, cts2.Token)
                .ConfigureAwait(false);

            using var responseDoc = JsonDocument.Parse(response);
            var root = responseDoc.RootElement;

            Assert.IsTrue(root.TryGetProperty("result", out var result));
            Assert.IsTrue(result.TryGetProperty("tools", out var tools));
            Assert.IsGreaterThan(0, tools.GetArrayLength());

            var toolNames = new List<string>();
            foreach(var tool in tools.EnumerateArray())
            {
                if(tool.TryGetProperty("name", out var name))
                {
                    toolNames.Add(name.GetString() ?? "");
                }
            }

            Assert.IsGreaterThan(0, toolNames.Count, "Should have at least one tool registered.");

            Assert.Contains(McpToolNames.GetTpmInfo, toolNames);
            Assert.Contains(McpToolNames.CheckTpmSupport, toolNames);
            Assert.Contains(McpToolNames.CreateDid, toolNames);
            Assert.Contains(McpToolNames.ListDids, toolNames);
        }
        finally
        {
            await VerifiableCliTestHelpers.EnsureProcessTerminatedAsync(process, TestContext.CancellationToken)
                .ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Tests connecting to the MCP server using the official client SDK via stdio.
    /// </summary>
    [TestMethod]
    [TestCategory("McpClient")]
    public async Task McpClientConnectsToServerViaStdio()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");
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
            var toolNames = tools.Select(t => t.Name).ToList();

            Assert.IsGreaterThan(0, tools.Count);
            Assert.Contains(McpToolNames.CheckTpmSupport, toolNames);
            Assert.Contains(McpToolNames.ListDids, toolNames);

            var result = await client.CallToolAsync(
                McpToolNames.ListDids,
                new Dictionary<string, object?>(),
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsNotNull(result);
        }
    }


    /// <summary>
    /// Sends a JSON-RPC message to the MCP server process via stdin.
    /// </summary>
    private static async Task SendMessageAsync(
        System.Diagnostics.Process process,
        string message,
        CancellationToken cancellationToken)
    {
        await process.StandardInput.WriteLineAsync(message.AsMemory(), cancellationToken)
            .ConfigureAwait(false);
        await process.StandardInput.FlushAsync(cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Reads lines from the MCP server stdout until a JSON-RPC response with the
    /// expected id is found. Notifications and other messages are skipped.
    /// </summary>
    /// <param name="process">The MCP server process.</param>
    /// <param name="expectedId">The JSON-RPC request id to match.</param>
    /// <param name="cancellationToken">Cancellation token that should include a timeout.</param>
    /// <returns>The raw JSON string of the matching response.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the server closes stdout before sending the expected response.
    /// </exception>
    private static async Task<string> ReadResponseByIdAsync(
        System.Diagnostics.Process process,
        int expectedId,
        CancellationToken cancellationToken)
    {
        while(true)
        {
            string? line = await VerifiableCliTestHelpers.ReadLineWithTimeoutAsync(
                process.StandardOutput, cancellationToken)
                .ConfigureAwait(false);

            if(line is null)
            {
                throw new InvalidOperationException(
                    $"Server closed stdout before responding to request id {expectedId}.");
            }

            //Try to parse and match the id. Skip notifications and other messages.
            using var doc = JsonDocument.Parse(line);
            if(doc.RootElement.TryGetProperty("id", out var idElement) &&
               idElement.TryGetInt32(out int id) &&
               id == expectedId)
            {
                return line;
            }
        }
    }
}