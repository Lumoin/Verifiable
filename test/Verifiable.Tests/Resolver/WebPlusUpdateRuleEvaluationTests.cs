using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using Verifiable.Core.Did.Methods.WebPlus;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusUpdateRuleEvaluation.IsSatisfied"/> — the did:webplus updateRules satisfaction
/// (did:webplus Draft v0.4, Update Rules, WP-UR-2..7). Each form is exercised in both its satisfied and
/// unsatisfied state, including weighted thresholds and nesting.
/// </summary>
[TestClass]
internal sealed class WebPlusUpdateRuleEvaluationTests
{
    private const string KeyA = "uKEYa";
    private const string KeyB = "uKEYb";
    private const string KeyC = "uKEYc";
    private const string PreRotationKey = "uKEYpre";
    private const string PreRotationHash = "uHASHpre";


    /// <summary>A matcher pairing the single pre-rotation key with its committed MBHash; no other pair matches.</summary>
    private static ValueTask<bool> Matcher(string mbPubKey, string mbHash, CancellationToken cancellationToken)
    {
        return ValueTask.FromResult(mbPubKey == PreRotationKey && mbHash == PreRotationHash);
    }


    /// <summary>Builds an ordinal key set.</summary>
    private static HashSet<string> Keys(params string[] keys)
    {
        return new HashSet<string>(keys, StringComparer.Ordinal);
    }


    /// <summary>Evaluates a rule against a key set, with the pre-rotation matcher.</summary>
    private static async Task<bool> Evaluate(WebPlusUpdateRule rule, IReadOnlySet<string> keys)
    {
        return await WebPlusUpdateRuleEvaluation.IsSatisfiedAsync(rule, keys, Matcher, CancellationToken.None);
    }


    /// <summary>WP-UR-2: <c>{}</c> is never satisfied, even with keys present.</summary>
    [TestMethod]
    public async Task DisallowIsNeverSatisfied()
    {
        Assert.IsFalse(await Evaluate(new DisallowUpdateRule(), Keys(KeyA, KeyB)));
    }


    /// <summary>WP-UR-3: <c>{"key"}</c> is satisfied exactly when that key produced a proof.</summary>
    [TestMethod]
    public async Task KeyIsSatisfiedByItsKey()
    {
        Assert.IsTrue(await Evaluate(new KeyUpdateRule(KeyA), Keys(KeyA)));
        Assert.IsFalse(await Evaluate(new KeyUpdateRule(KeyA), Keys(KeyB)));
    }


    /// <summary>WP-UR-4: <c>{"hashedKey"}</c> is satisfied by a key hashing to the committed MBHash.</summary>
    [TestMethod]
    public async Task HashedKeyIsSatisfiedByPreRotationKey()
    {
        Assert.IsTrue(await Evaluate(new HashedKeyUpdateRule(PreRotationHash), Keys(PreRotationKey)));
        Assert.IsFalse(await Evaluate(new HashedKeyUpdateRule(PreRotationHash), Keys(KeyA)));
    }


    /// <summary>WP-UR-5: <c>{"any"}</c> is satisfied when at least one sub-rule is satisfied.</summary>
    [TestMethod]
    public async Task AnyIsSatisfiedByOneSubRule()
    {
        var rule = new AnyUpdateRule(ImmutableArray.Create<WebPlusUpdateRule>(new KeyUpdateRule(KeyA), new KeyUpdateRule(KeyB)));

        Assert.IsTrue(await Evaluate(rule, Keys(KeyB)));
        Assert.IsFalse(await Evaluate(rule, Keys(KeyC)));
    }


    /// <summary>WP-UR-6: <c>{"all"}</c> is satisfied only when every sub-rule is satisfied.</summary>
    [TestMethod]
    public async Task AllRequiresEverySubRule()
    {
        var rule = new AllUpdateRule(ImmutableArray.Create<WebPlusUpdateRule>(new KeyUpdateRule(KeyA), new KeyUpdateRule(KeyB)));

        Assert.IsTrue(await Evaluate(rule, Keys(KeyA, KeyB)));
        Assert.IsFalse(await Evaluate(rule, Keys(KeyA)));
    }


    /// <summary>WP-UR-7: <c>{"atLeast"}</c> is satisfied when the summed weights of satisfied sub-rules reach the threshold.</summary>
    [TestMethod]
    public async Task AtLeastSumsUnitWeightsToThreshold()
    {
        var rule = new AtLeastUpdateRule(2, ImmutableArray.Create(
            new WeightedUpdateRule(1, new KeyUpdateRule(KeyA)),
            new WeightedUpdateRule(1, new KeyUpdateRule(KeyB)),
            new WeightedUpdateRule(1, new KeyUpdateRule(KeyC))));

        Assert.IsTrue(await Evaluate(rule, Keys(KeyA, KeyB)));
        Assert.IsFalse(await Evaluate(rule, Keys(KeyA)));
    }


    /// <summary>WP-UR-7: a heavier weight can reach the threshold alone.</summary>
    [TestMethod]
    public async Task AtLeastRespectsWeights()
    {
        var rule = new AtLeastUpdateRule(2, ImmutableArray.Create(
            new WeightedUpdateRule(2, new KeyUpdateRule(KeyA)),
            new WeightedUpdateRule(1, new KeyUpdateRule(KeyB))));

        Assert.IsTrue(await Evaluate(rule, Keys(KeyA)), "A weight-2 key alone reaches the threshold of 2.");
        Assert.IsFalse(await Evaluate(rule, Keys(KeyB)), "A weight-1 key alone does not reach the threshold of 2.");
    }


    /// <summary>A nested rule (<c>any</c> of an <c>all</c> and a <c>key</c>) folds composite sub-results correctly.</summary>
    [TestMethod]
    public async Task NestedAnyOfAllAndKey()
    {
        var rule = new AnyUpdateRule(ImmutableArray.Create<WebPlusUpdateRule>(
            new AllUpdateRule(ImmutableArray.Create<WebPlusUpdateRule>(new KeyUpdateRule(KeyA), new KeyUpdateRule(KeyB))),
            new KeyUpdateRule(KeyC)));

        Assert.IsTrue(await Evaluate(rule, Keys(KeyC)), "The single key branch satisfies the any.");
        Assert.IsTrue(await Evaluate(rule, Keys(KeyA, KeyB)), "The all branch satisfies the any.");
        Assert.IsFalse(await Evaluate(rule, Keys(KeyA)), "Neither branch is satisfied.");
    }


    /// <summary>An <c>atLeast</c> whose sub-rule is itself a composite applies the composite's weight on satisfaction.</summary>
    [TestMethod]
    public async Task AtLeastWithCompositeSubRule()
    {
        var rule = new AtLeastUpdateRule(1, ImmutableArray.Create(
            new WeightedUpdateRule(1, new AllUpdateRule(ImmutableArray.Create<WebPlusUpdateRule>(new KeyUpdateRule(KeyA), new KeyUpdateRule(KeyB)))),
            new WeightedUpdateRule(1, new KeyUpdateRule(KeyC))));

        Assert.IsTrue(await Evaluate(rule, Keys(KeyA, KeyB)), "The composite branch is satisfied, contributing weight 1.");
        Assert.IsFalse(await Evaluate(rule, Keys(KeyA)), "Neither weighted branch is satisfied.");
    }
}
