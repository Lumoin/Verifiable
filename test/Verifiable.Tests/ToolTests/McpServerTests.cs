using ModelContextProtocol.Client;
using System.Text.Json;

namespace Verifiable.Tests.ToolTests;

/// <summary>
/// Tests for the shared operations and MCP server functionality.
/// </summary>
[TestClass]
public class McpServerTests
{
    /// <summary>
    /// Gets or sets the context information for the current test run, including test metadata and utilities for logging
    /// and result tracking.
    /// </summary>
    /// <remarks>Use this property to access details about the executing test, such as its name, outcome, and
    /// associated data. The property is typically set by the test framework and should not be assigned manually in user
    /// code.</remarks>
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void CheckTpmSupportMessageReturnsValidResponse()
    {
        string result = VerifiableOperations.CheckTpmSupportMessage();

        Assert.IsNotNull(result);
        Assert.IsGreaterThan(0, result.Length);
        Assert.Contains("supported", result, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("platform", result, StringComparison.OrdinalIgnoreCase);
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
    public void GetTpmInfoAsJsonReturnsValidJsonOrError()
    {
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
    public async Task SaveTpmInfoToFileAsyncReturnsExpectedResult()
    {
        string testFilePath = Path.Combine(Path.GetTempPath(), $"test_tpm_{Guid.NewGuid()}.json");

        try
        {
            var result = await VerifiableOperations.SaveTpmInfoToFileAsync(testFilePath);

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
    public async Task SaveTpmInfoToFileAsyncNullPathUsesDefaultFileName()
    {
        var result = await VerifiableOperations.SaveTpmInfoToFileAsync(null);

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
        Assert.Contains(int.MaxValue.ToString(), maxResult.Value!, StringComparison.Ordinal);

        var minResult = VerifiableOperations.CreateDid(int.MinValue, "param", null);
        Assert.IsTrue(minResult.IsSuccess);
        Assert.Contains(int.MinValue.ToString(), minResult.Value!, StringComparison.Ordinal);

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
        string longParam = new string('x', 10000);

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

            return;
        }

        using var process = VerifiableCliTestHelpers.CreateMcpServerProcess(executablePath);

        try
        {
            process.Start();
            await Task.Delay(500, TestContext.CancellationToken);

            Assert.IsFalse(process.HasExited, "MCP server should still be running after startup.");

            var initializeRequest = new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new
                {
                    protocolVersion = "2025-11-25",
                    capabilities = new { },
                    clientInfo = new
                    {
                        name = "test-client",
                        version = "1.0.0"
                    }
                }
            };

            string requestJson = JsonSerializer.Serialize(initializeRequest);
            await process.StandardInput.WriteLineAsync(requestJson.AsMemory(), TestContext.CancellationToken);
            await process.StandardInput.FlushAsync(TestContext.CancellationToken);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            string? response = await VerifiableCliTestHelpers.ReadLineWithTimeoutAsync(process.StandardOutput, cts.Token);

            Assert.IsNotNull(response, "Should receive a response from MCP server.");

            using var responseDoc = JsonDocument.Parse(response);
            var root = responseDoc.RootElement;

            Assert.IsTrue(root.TryGetProperty("jsonrpc", out var jsonrpc));
            Assert.AreEqual("2.0", jsonrpc.GetString());

            Assert.IsTrue(root.TryGetProperty("id", out var id));
            Assert.AreEqual(1, id.GetInt32());

            Assert.IsTrue(root.TryGetProperty("result", out _), "Should have result property.");
        }
        finally
        {
            await VerifiableCliTestHelpers.EnsureProcessTerminatedAsync(process, TestContext.CancellationToken);
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

            return;
        }

        using var process = VerifiableCliTestHelpers.CreateMcpServerProcess(executablePath);

        try
        {
            process.Start();

            var initRequest = JsonSerializer.Serialize(new
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

            await process.StandardInput.WriteLineAsync(initRequest.AsMemory(), TestContext.CancellationToken);
            await process.StandardInput.FlushAsync(TestContext.CancellationToken);

            using var cts1 = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            cts1.CancelAfter(TimeSpan.FromSeconds(5));
            await VerifiableCliTestHelpers.ReadLineWithTimeoutAsync(process.StandardOutput, cts1.Token);

            var initializedNotification = JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                method = "notifications/initialized"
            });

            await process.StandardInput.WriteLineAsync(initializedNotification.AsMemory(), TestContext.CancellationToken);
            await process.StandardInput.FlushAsync(TestContext.CancellationToken);

            var toolsRequest = JsonSerializer.Serialize(new
            {
                jsonrpc = "2.0",
                id = 2,
                method = "tools/list"
            });

            await process.StandardInput.WriteLineAsync(toolsRequest.AsMemory(), TestContext.CancellationToken);
            await process.StandardInput.FlushAsync(TestContext.CancellationToken);

            using var cts2 = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            cts2.CancelAfter(TimeSpan.FromSeconds(5));
            string? response = await VerifiableCliTestHelpers.ReadLineWithTimeoutAsync(process.StandardOutput, cts2.Token);

            Assert.IsNotNull(response);

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
            await VerifiableCliTestHelpers.EnsureProcessTerminatedAsync(process, TestContext.CancellationToken);
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

            return;
        }

        var clientTransport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "Verifiable MCP Server",
            Command = executablePath,
            Arguments = ["-mcp"]
        });

        await using var client = await McpClient.CreateAsync(clientTransport, cancellationToken: TestContext.CancellationToken);

        var tools = await client.ListToolsAsync(cancellationToken: TestContext.CancellationToken);
        var toolNames = tools.Select(t => t.Name).ToList();

        Assert.IsGreaterThan(0, tools.Count);
        Assert.Contains(McpToolNames.CheckTpmSupport, toolNames);
        Assert.Contains(McpToolNames.ListDids, toolNames);

        var result = await client.CallToolAsync(
            McpToolNames.ListDids,
            new Dictionary<string, object?>(),
            cancellationToken: TestContext.CancellationToken);

        Assert.IsNotNull(result);
    }
}