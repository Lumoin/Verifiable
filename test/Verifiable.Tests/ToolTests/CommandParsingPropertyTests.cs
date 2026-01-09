using System.CommandLine;
using CsCheck;

namespace Verifiable.Tests.ToolTests;

/// <summary>
/// Property-based tests for command-line parsing using CsCheck.
/// </summary>
[TestClass]
public class CommandParsingPropertyTests
{
    [TestMethod]
    public void ParseDidCreateAnyValidIntegerIdSucceeds()
    {
        Gen.Int.Sample(id =>
        {
            var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(out var createIdArg, out _, out _);
            ParseResult result = rootCommand.Parse($"did create {id} param");

            Assert.IsEmpty(result.Errors);
            Assert.AreEqual(id, result.GetValue(createIdArg));
        });
    }


    [TestMethod]
    public void ParseDidCreateAnyAlphanumericParamSucceeds()
    {
        Gen.String[1, 100].Sample(param =>
        {
            //Filter characters that affect System.CommandLine parsing.
            //These are not bugs - they are intentional parser features (e.g. @ for response files).
            //Business logic is tested with arbitrary inputs in McpServerPropertyTests.
            if(VerifiableCliTestHelpers.IsUnsuitableForCliArgument(param) ||
               VerifiableCliTestHelpers.StartsWithSystemCommandLineBuiltInOption(param))
            {
                return;
            }

            var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(out _, out var createParamArg, out _);
            ParseResult result = rootCommand.Parse($"did create 1 {param}");

            Assert.IsEmpty(result.Errors);
            Assert.AreEqual(param, result.GetValue(createParamArg));
        });
    }


    [TestMethod]
    public void ParseDidCreateAnyParamWithQuotesSucceeds()
    {
        Gen.String[1, 100].Sample(param =>
        {
            //Filter characters that affect System.CommandLine parsing.
            //These are not bugs - they are intentional parser features (e.g. @ for response files).
            //Business logic is tested with arbitrary inputs in McpServerPropertyTests.
            if(VerifiableCliTestHelpers.ContainsCliSpecialCharacters(param) ||
               VerifiableCliTestHelpers.StartsWithSystemCommandLineBuiltInOption(param))
            {
                return;
            }

            var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(out _, out var createParamArg, out _);
            ParseResult result = rootCommand.Parse(["did", "create", "1", param]);

            Assert.IsEmpty(result.Errors);
            Assert.AreEqual(param, result.GetValue(createParamArg));
        });
    }


    [TestMethod]
    public void ParseDidRevokeAnyValidIntegerIdSucceeds()
    {
        Gen.Int.Sample(id =>
        {
            var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(out _, out _, out _);
            ParseResult result = rootCommand.Parse($"did revoke {id}");

            Assert.IsEmpty(result.Errors);
        });
    }


    [TestMethod]
    public void ParseDidViewAnyValidIntegerIdSucceeds()
    {
        Gen.Int.Sample(id =>
        {
            var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(out _, out _, out _);
            ParseResult result = rootCommand.Parse($"did view {id}");

            Assert.IsEmpty(result.Errors);
        });
    }


    [TestMethod]
    public void ParseDidCreateExtraParamAnyStringSucceeds()
    {
        Gen.String[0, 50].Sample(extra =>
        {
            //Filter characters that affect System.CommandLine parsing.
            //These are not bugs - they are intentional parser features (e.g. @ for response files).
            //Business logic is tested with arbitrary inputs in McpServerPropertyTests.
            if(VerifiableCliTestHelpers.IsUnsuitableForCliOptionValue(extra) ||
               VerifiableCliTestHelpers.StartsWithSystemCommandLineBuiltInOption(extra))
            {
                return;
            }

            var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(out _, out _, out var extraParamOpt);
            ParseResult result = rootCommand.Parse(["did", "create", "1", "param", "--extraParam", extra]);

            Assert.IsEmpty(result.Errors);
            Assert.AreEqual(extra, result.GetValue(extraParamOpt));
        });
    }


    [TestMethod]
    public void ParseDidCreateNonIntegerIdAlwaysFails()
    {
        //Exclude strings containing whitespace because System.CommandLine splits on whitespace,
        //so a string like "2 abc" would have "2" parsed as a valid integer id.
        //Also exclude strings starting with -? or -h which trigger help display without errors.
        Gen.String[1, 20].Where(s => !int.TryParse(s, out _) &&
                                     !string.IsNullOrWhiteSpace(s) &&
                                     !s.Any(char.IsWhiteSpace) &&
                                     !VerifiableCliTestHelpers.StartsWithSystemCommandLineBuiltInOption(s))
            .Sample(invalidId =>
            {
                var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(out _, out _, out _);
                ParseResult result = rootCommand.Parse($"did create {invalidId} param");

                Assert.IsNotEmpty(result.Errors);
            });
    }


    [TestMethod]
    public void ParseRandomUnknownCommandAlwaysFails()
    {
        Gen.String[1, 20].Where(s => !IsKnownCommandOrBuiltInOption(s) && !string.IsNullOrWhiteSpace(s))
            .Sample(unknownCommand =>
            {
                var rootCommand = VerifiableCliTestHelpers.BuildTestableRootCommand(out _, out _, out _);
                ParseResult result = rootCommand.Parse(unknownCommand);

                Assert.IsNotEmpty(result.Errors);
            });
    }


    /// <summary>
    /// Determines whether the input matches a known command or could be interpreted
    /// as a System.CommandLine built-in option. This includes prefix matching
    /// for options like -h, /h (help) and -?, /? which parse without errors.
    /// </summary>
    private static bool IsKnownCommandOrBuiltInOption(string input)
    {
        if(string.Equals(input, "did", StringComparison.OrdinalIgnoreCase) ||
           string.Equals(input, "info", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return VerifiableCliTestHelpers.StartsWithSystemCommandLineBuiltInOption(input);
    }
}