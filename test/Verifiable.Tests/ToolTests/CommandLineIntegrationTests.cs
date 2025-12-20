namespace Verifiable.Tests.ToolTests;

/// <summary>
/// Integration tests that execute the actual command-line tool as a process.
/// These tests verify end-to-end behavior including process startup, argument handling, and exit codes.
/// </summary>
[TestClass]
public class CommandLineIntegrationTests
{
    /// <summary>
    /// The MSTest context for the current test run.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public async Task CliDidCreateReturnsSuccessExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did create 123 testParam", TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stdout.Length);
    }


    [TestMethod]
    public async Task CliDidCreateWithExtraParamReturnsSuccessExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did create 456 myParam --extraParam extra", TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stdout.Length);
    }


    [TestMethod]
    public async Task CliDidRevokeReturnsSuccessExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did revoke 789", TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stdout.Length);
    }


    [TestMethod]
    public async Task CliDidListReturnsSuccessExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did list", TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stdout.Length);
    }


    [TestMethod]
    public async Task CliDidViewReturnsSuccessExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did view 42", TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stdout.Length);
    }


    [TestMethod]
    public async Task CliHelpReturnsSuccessExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "--help", TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("did", result.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("info", result.Stdout, StringComparison.OrdinalIgnoreCase);
    }


    [TestMethod]
    public async Task CliDidHelpReturnsSuccessExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did --help", TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains("create", result.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("revoke", result.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("list", result.Stdout, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("view", result.Stdout, StringComparison.OrdinalIgnoreCase);
    }


    [TestMethod]
    public async Task CliVersionReturnsSuccessExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "--version", TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
    }


    [TestMethod]
    public async Task CliInvalidCommandReturnsNonZeroExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "unknowncommand", TestContext.CancellationToken);

        Assert.AreNotEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stderr.Length);
    }


    [TestMethod]
    public async Task CliDidCreateMissingArgsReturnsNonZeroExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did create", TestContext.CancellationToken);

        Assert.AreNotEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stderr.Length);
    }


    [TestMethod]
    public async Task CliDidCreateInvalidIdReturnsNonZeroExitCode()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did create notAnInt param", TestContext.CancellationToken);

        Assert.AreNotEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stderr.Length);
    }


    [TestMethod]
    public async Task CliDidCreateUnicodeParameterSucceeds()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        string unicodeParam = "Wano_国_Gateway";
        var result = await VerifiableCliTestHelpers.RunCliAsync(executablePath, ["did", "create", "1500000000", unicodeParam], TestContext.CancellationToken);

        Assert.AreEqual(0, result.ExitCode);
        Assert.IsGreaterThan(0, result.Stdout.Length);
    }


    [TestMethod]
    public async Task CliDidCreateBoundaryValuesSucceed()
    {
        string? executablePath = VerifiableCliTestHelpers.GetExecutablePath();
        if(executablePath is null)
        {
            Assert.Inconclusive("Executable not found. Build the project first.");

            return;
        }

        var maxResult = await VerifiableCliTestHelpers.RunCliAsync(executablePath, $"did create {int.MaxValue} param", TestContext.CancellationToken);
        var minResult = await VerifiableCliTestHelpers.RunCliAsync(executablePath, $"did create {int.MinValue} param", TestContext.CancellationToken);
        var zeroResult = await VerifiableCliTestHelpers.RunCliAsync(executablePath, "did create 0 param", TestContext.CancellationToken);

        Assert.AreEqual(0, maxResult.ExitCode);
        Assert.AreEqual(0, minResult.ExitCode);
        Assert.AreEqual(0, zeroResult.ExitCode);
    }
}