using System.CommandLine;

namespace Verifiable.Tests.ToolTests;


/// <summary>
/// Tests for command-line parsing behavior and command invocation.
/// </summary>
[TestClass]
public class CommandParsingTests
{
    [TestMethod]
    public void ParseDidCreateValidArgumentsNoErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out var createParamArg, out var extraParamOpt,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did create 123 myParam");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(123, result.GetValue(createIdArg));
        Assert.AreEqual("myParam", result.GetValue(createParamArg));
        Assert.IsNull(result.GetValue(extraParamOpt));
    }


    [TestMethod]
    public void ParseDidCreateWithExtraParamParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out var createParamArg, out var extraParamOpt,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did create 456 testParam --extraParam someExtra");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(456, result.GetValue(createIdArg));
        Assert.AreEqual("testParam", result.GetValue(createParamArg));
        Assert.AreEqual("someExtra", result.GetValue(extraParamOpt));
    }


    [TestMethod]
    public void ParseDidCreateWithShortExtraParamParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out var createParamArg, out var extraParamOpt,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did create 789 param -e shortForm");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual("shortForm", result.GetValue(extraParamOpt));
    }


    [TestMethod]
    public void ParseDidCreateUsingAliasParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out var createParamArg, out _,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did new 100 aliasParam");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(100, result.GetValue(createIdArg));
        Assert.AreEqual("aliasParam", result.GetValue(createParamArg));
    }


    [TestMethod]
    public void ParseDidRevokeValidIdNoErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out var revokeIdArg, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did revoke 999");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(999, result.GetValue(revokeIdArg));
    }


    [TestMethod]
    public void ParseDidListNoArgumentsNoErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did list");

        Assert.IsEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseDidViewValidIdNoErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out var viewIdArg,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did view 42");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(42, result.GetValue(viewIdArg));
    }


    [TestMethod]
    public void ParseInfoTpmNoArgumentsNoErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("info tpm");

        Assert.IsEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseDidCreateMissingRequiredArgumentsHasErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did create");

        Assert.IsNotEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseDidCreateInvalidIdTypeHasErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did create notAnInt myParam");

        Assert.IsNotEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseUnknownCommandHasErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("unknown command");

        Assert.IsNotEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseUnknownOptionHasErrors()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did create 1 param --unknownOption value");

        Assert.IsNotEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseHelpOptionRecognizedWithoutError()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("--help");

        Assert.IsEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseSubcommandHelpRecognizedWithoutError()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did --help");

        Assert.IsEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseVersionOptionRecognizedWithoutError()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("--version");

        Assert.IsEmpty(result.Errors);
    }


    [TestMethod]
    public void InvokeDidCreateReturnsSuccessExitCode()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out var createParamArg, out var extraParamOpt,
            out _, out _, out var didCreateCommand, out _, out _, out _, out _);

        int? capturedId = null;
        string? capturedParam = null;
        string? capturedExtra = null;

        didCreateCommand.SetAction(parseResult =>
        {
            capturedId = parseResult.GetValue(createIdArg);
            capturedParam = parseResult.GetValue(createParamArg);
            capturedExtra = parseResult.GetValue(extraParamOpt);

            return 0;
        });

        int exitCode = rootCommand.Parse("did create 123 testParam --extraParam extra").Invoke();

        Assert.AreEqual(0, exitCode);
        Assert.AreEqual(123, capturedId);
        Assert.AreEqual("testParam", capturedParam);
        Assert.AreEqual("extra", capturedExtra);
    }


    [TestMethod]
    public void InvokeDidRevokeReturnsSuccessExitCode()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out var revokeIdArg, out _,
            out _, out var didRevokeCommand, out _, out _, out _);

        int? capturedId = null;

        didRevokeCommand.SetAction(parseResult =>
        {
            capturedId = parseResult.GetValue(revokeIdArg);

            return 0;
        });

        int exitCode = rootCommand.Parse("did revoke 456").Invoke();

        Assert.AreEqual(0, exitCode);
        Assert.AreEqual(456, capturedId);
    }


    [TestMethod]
    public void InvokeDidListReturnsSuccessExitCode()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out var didListCommand, out _, out _);

        bool commandExecuted = false;

        didListCommand.SetAction(_ =>
        {
            commandExecuted = true;

            return 0;
        });

        int exitCode = rootCommand.Parse("did list").Invoke();

        Assert.AreEqual(0, exitCode);
        Assert.IsTrue(commandExecuted);
    }


    [TestMethod]
    public void InvokeDidViewReturnsSuccessExitCode()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out var viewIdArg,
            out _, out _, out _, out var didViewCommand, out _);

        int? capturedId = null;

        didViewCommand.SetAction(parseResult =>
        {
            capturedId = parseResult.GetValue(viewIdArg);

            return 0;
        });

        int exitCode = rootCommand.Parse("did view 789").Invoke();

        Assert.AreEqual(0, exitCode);
        Assert.AreEqual(789, capturedId);
    }


    [TestMethod]
    public void InvokeInvalidArgumentsReturnsNonZeroExitCode()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        int exitCode = rootCommand.Parse("did create notANumber param").Invoke();

        Assert.AreNotEqual(0, exitCode);
    }


    [TestMethod]
    public void ParseDidCreateUnicodeParameterParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out var createParamArg, out _,
            out _, out _, out _, out _, out _, out _, out _);

        string unicodeParam = "Alabasta_航海_🏴‍☠️";
        ParseResult result = rootCommand.Parse($"did create 1500000000 \"{unicodeParam}\"");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(1500000000, result.GetValue(createIdArg));
        Assert.AreEqual(unicodeParam, result.GetValue(createParamArg));
    }


    [TestMethod]
    public void ParseDidCreateSpecialCharactersParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out var createParamArg, out _,
            out _, out _, out _, out _, out _, out _, out _);

        string specialParam = "test with spaces & special <chars>";
        ParseResult result = rootCommand.Parse(["did", "create", "1", specialParam]);

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(specialParam, result.GetValue(createParamArg));
    }


    [TestMethod]
    public void ParseDidCreateEmptyStringParameterParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out var createParamArg, out _,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse(["did", "create", "1", ""]);

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual("", result.GetValue(createParamArg));
    }


    [TestMethod]
    public void ParseDidCreateMaxIntIdParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out _, out _,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse($"did create {int.MaxValue} param");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(int.MaxValue, result.GetValue(createIdArg));
    }


    [TestMethod]
    public void ParseDidCreateMinIntIdParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out _, out _,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse($"did create {int.MinValue} param");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(int.MinValue, result.GetValue(createIdArg));
    }


    [TestMethod]
    public void ParseDidCreateZeroIdParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out _, out _,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did create 0 param");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(0, result.GetValue(createIdArg));
    }


    [TestMethod]
    public void ParseDidCreateNegativeIdParsesCorrectly()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out var createIdArg, out _, out _,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("did create -42 param");

        Assert.IsEmpty(result.Errors);
        Assert.AreEqual(-42, result.GetValue(createIdArg));
    }


    [TestMethod]
    public void ParseCommandsAreCaseSensitiveByDefault()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("DID CREATE 1 param");

        Assert.IsNotEmpty(result.Errors);
    }


    [TestMethod]
    public void ParseOptionsCaseVariations()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out var extraParamOpt,
            out _, out _, out _, out _, out _, out _, out _);

        ParseResult lowerResult = rootCommand.Parse("did create 1 param --extraparam value");
        ParseResult correctResult = rootCommand.Parse("did create 1 param --extraParam value");

        bool lowerHasErrorsOrNull = lowerResult.Errors.Count > 0 || lowerResult.GetValue(extraParamOpt) == null;
        Assert.IsTrue(lowerHasErrorsOrNull);
        Assert.AreEqual("value", correctResult.GetValue(extraParamOpt));
    }


    [TestMethod]
    public void ParseMcpArgumentShouldNotBeHandledByMainCommands()
    {
        var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(
            out _, out _, out _, out _, out _,
            out _, out _, out _, out _, out _);

        ParseResult result = rootCommand.Parse("-mcp");

        Assert.IsNotEmpty(result.Errors);
    }
}