using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using CsCheck;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Json;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Property-based tests (CsCheck) for the did:webplus update-rule parser and evaluator. Two invariants: the
/// security invariant that <strong>no well-formed rule is satisfied by an empty key set</strong> — after the
/// strict parser rejects the degenerate always-satisfied forms (empty <c>all</c>, non-positive <c>atLeast</c>),
/// every non-root update requires at least one valid proof — and parser robustness, that a one-edit mutation of a
/// valid <c>updateRules</c> is either parsed or rejected with a <see cref="JsonException"/>, never another
/// exception type. The mutation generator edits known-valid material rather than sampling blindly, because the
/// parser rejects almost all blind-random input at the first token but a near-valid neighbour reaches the
/// threshold/weight/array arithmetic where the defects live.
/// </summary>
[TestClass]
internal sealed class WebPlusUpdateRulePropertyTests
{
    /// <summary>The empty satisfied-key set: the set a non-root document that carries no valid proof produces.</summary>
    private static IReadOnlySet<string> EmptyKeySet { get; } = new HashSet<string>(System.StringComparer.Ordinal);


    /// <summary>A hashed-key matcher that never matches; the empty-key-set invariant holds regardless of it.</summary>
    private static ValueTask<bool> NeverMatches(string mbPubKey, string mbHash, CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(false);
    }


    /// <summary>A leaf rule: a <c>key</c> or <c>hashedKey</c> rule over a distinct placeholder value.</summary>
    private static Gen<WebPlusUpdateRule> GenLeaf { get; } =
        Gen.OneOf(
            Gen.Int[0, 999].Select(i => (WebPlusUpdateRule)new KeyUpdateRule("uKEY" + i)),
            Gen.Int[0, 999].Select(i => (WebPlusUpdateRule)new HashedKeyUpdateRule("uHASH" + i)));


    /// <summary>Known-valid <c>updateRules</c> expressions spanning the forms, the seeds for one-edit mutation.</summary>
    private static string[] ValidUpdateRulesJson { get; } =
    [
        """{"key":"u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg"}""",
        """{"hashedKey":"uHiCMmFumKCTx6yxWPtoRM_VZj4DvdcHs2KEBK941pr8SXQ"}""",
        """{"any":[{"key":"uA"},{"key":"uB"}]}""",
        """{"all":[{"key":"uA"},{"hashedKey":"uH"}]}""",
        """{"atLeast":2,"of":[{"weight":2,"key":"uA"},{"key":"uB"}]}"""
    ];


    /// <summary>A character drawn from the Base64URL alphabet plus off-alphabet octets a parser must handle.</summary>
    private static Gen<char> GenAnyChar { get; } =
        Gen.OneOf(
            Gen.Char['A', 'Z'],
            Gen.Char['a', 'z'],
            Gen.Char['0', '9'],
            Gen.Const('-'),
            Gen.Const('_'),
            Gen.Const('"'),
            Gen.Const('{'),
            Gen.Const('}'),
            Gen.Const('['),
            Gen.Const(']'),
            Gen.Const(' '),
            Gen.Const('\0'));


    /// <summary>A one-edit mutation (substitute, truncate, or append) of a known-valid <c>updateRules</c> expression.</summary>
    private static Gen<string> GenMutatedUpdateRules { get; } =
        from seed in Gen.Int[0, ValidUpdateRulesJson.Length - 1]
        from mutation in Gen.Int[0, 2]
        from position in Gen.Int[0, ValidUpdateRulesJson[seed].Length]
        from character in GenAnyChar
        select Mutate(ValidUpdateRulesJson[seed], mutation, position, character);


    /// <summary>
    /// No well-formed did:webplus update rule is satisfied by an empty set of proof keys: after the strict parser
    /// rejects the degenerate forms, a rule leaf requires its key, and every composite requires at least one
    /// satisfied child (an <c>all</c>/<c>any</c> is non-empty, an <c>atLeast</c> threshold is positive), so a
    /// non-root document that carries no valid proof can never satisfy its predecessor's updateRules.
    /// </summary>
    [TestMethod]
    public void NoWellFormedRuleIsSatisfiedByAnEmptyKeySet() =>
        GenRuleOfDepth(3).Sample(rule => !IsSatisfiedByEmptyKeySet(rule));


    //Evaluates a rule against the empty key set. Evaluation completes synchronously — a hashed-key leaf iterates
    //the empty key set without invoking the matcher — so the ValueTask is converted to a Task to observe its
    //result without a ValueTask.Result access (CA2012).
    private static bool IsSatisfiedByEmptyKeySet(WebPlusUpdateRule rule)
    {
        return WebPlusUpdateRuleEvaluation.IsSatisfiedAsync(rule, EmptyKeySet, NeverMatches, CancellationToken.None)
            .AsTask().GetAwaiter().GetResult();
    }


    /// <summary>
    /// Parsing a one-edit mutation of a valid <c>updateRules</c> either succeeds or is rejected with a
    /// <see cref="JsonException"/> — never another exception type (an overflow, an out-of-range index, an
    /// argument error). Any other escaping exception fails the property with its shrunk seed.
    /// </summary>
    [TestMethod]
    public void ParsingMutatedUpdateRulesThrowsOnlyJsonException() =>
        GenMutatedUpdateRules.Sample(rules =>
        {
            byte[] document = Encoding.UTF8.GetBytes($$"""{"updateRules":{{rules}}}""");
            try
            {
                _ = WebPlusUpdateRulesJson.Parser(document);

                return true;
            }
            catch(JsonException)
            {
                return true;
            }
        });


    //A bounded generator of well-formed rule trees: a leaf at depth 0, otherwise a leaf or a non-empty
    //any/all/atLeast composite whose children are one level shallower. Every atLeast has a positive threshold and
    //positive weights, matching what the strict parser accepts.
    private static Gen<WebPlusUpdateRule> GenRuleOfDepth(int depth)
    {
        if(depth <= 0)
        {
            return GenLeaf;
        }

        Gen<WebPlusUpdateRule> child = GenRuleOfDepth(depth - 1);

        Gen<WebPlusUpdateRule> any = child.Array[1, 3].Select(rules => (WebPlusUpdateRule)new AnyUpdateRule([.. rules]));
        Gen<WebPlusUpdateRule> all = child.Array[1, 3].Select(rules => (WebPlusUpdateRule)new AllUpdateRule([.. rules]));
        Gen<WebPlusUpdateRule> atLeast =
            from rules in child.Array[1, 3]
            from weights in Gen.Int[1, 3].Array[rules.Length]
            from threshold in Gen.Int[1, 9]
            select (WebPlusUpdateRule)new AtLeastUpdateRule(threshold, [.. rules.Select((rule, index) => new WeightedUpdateRule(weights[index], rule))]);

        return Gen.OneOf(GenLeaf, any, all, atLeast);
    }


    //Applies a single edit to a known-valid string: substitute the character at a position, truncate to a
    //position, or append a character. A substitution past the end degenerates to an append.
    private static string Mutate(string text, int mutation, int position, char character) => mutation switch
    {
        0 => position < text.Length ? string.Concat(text.AsSpan(0, position), character.ToString(), text.AsSpan(position + 1)) : text + character,
        1 => text[..System.Math.Min(position, text.Length)],
        _ => text + character
    };
}
