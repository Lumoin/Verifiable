using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Did.Methods.WebPlus;
using Verifiable.Json;

namespace Verifiable.Tests.Resolver;

/// <summary>
/// Tests for <see cref="WebPlusUpdateRulesJson"/> — parsing a did:webplus <c>updateRules</c> expression into the
/// <see cref="WebPlusUpdateRule"/> tree (did:webplus Draft v0.4, Update Rules; WP-UR-1). Covers every defined
/// form, the weighted <c>atLeast</c> shape, nesting, malformed-input rejection, and that the parsed tree drives
/// <see cref="WebPlusUpdateRuleEvaluation"/> as expected.
/// </summary>
[TestClass]
internal sealed class WebPlusUpdateRulesJsonTests
{
    private static WebPlusUpdateRuleParser Parser => WebPlusUpdateRulesJson.Parser;

    //A HashedKeyMatcher that never matches; the key-only and structural tests never reach a hashedKey rule.
    private static readonly HashedKeyMatcher NoHashedKeyMatch = static (_, _, _) => ValueTask.FromResult(false);


    //Parses a standalone updateRules value by wrapping it in a minimal DID document, the form the parser reads.
    private static WebPlusUpdateRule Parse(string updateRulesJson)
    {
        byte[] document = Encoding.UTF8.GetBytes($$"""{"updateRules": {{updateRulesJson}}}""");

        return Parser(document);
    }


    /// <summary>The empty object is the disallow (deactivation tombstone) rule (WP-UR-2).</summary>
    [TestMethod]
    public void ParsesEmptyObjectAsDisallow()
    {
        Assert.IsInstanceOfType<DisallowUpdateRule>(Parse("{}"));
    }


    /// <summary>A <c>key</c> rule parses to a <see cref="KeyUpdateRule"/> carrying the MBPubKey (WP-UR-3).</summary>
    [TestMethod]
    public void ParsesKeyRule()
    {
        var rule = (KeyUpdateRule)Parse("""{"key":"u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg"}""");

        Assert.AreEqual("u7QFCWKaWNQ5FsNShO8BlZwjHa5xkGleeETKwu-vjf1SZXg", rule.MbPubKey);
    }


    /// <summary>A <c>hashedKey</c> rule parses to a <see cref="HashedKeyUpdateRule"/> carrying the MBHash (WP-UR-4).</summary>
    [TestMethod]
    public void ParsesHashedKeyRule()
    {
        var rule = (HashedKeyUpdateRule)Parse("""{"hashedKey":"uHiCMmFumKCTx6yxWPtoRM_VZj4DvdcHs2KEBK941pr8SXQ"}""");

        Assert.AreEqual("uHiCMmFumKCTx6yxWPtoRM_VZj4DvdcHs2KEBK941pr8SXQ", rule.MbHash);
    }


    /// <summary>An <c>any</c> rule parses to an <see cref="AnyUpdateRule"/> over its sub-rules (WP-UR-5).</summary>
    [TestMethod]
    public void ParsesAnyRule()
    {
        var rule = (AnyUpdateRule)Parse("""{"any":[{"key":"uA"},{"key":"uB"}]}""");

        Assert.HasCount(2, rule.Rules);
        Assert.AreEqual("uA", ((KeyUpdateRule)rule.Rules[0]).MbPubKey);
        Assert.AreEqual("uB", ((KeyUpdateRule)rule.Rules[1]).MbPubKey);
    }


    /// <summary>An <c>all</c> rule parses to an <see cref="AllUpdateRule"/> over its sub-rules (WP-UR-6).</summary>
    [TestMethod]
    public void ParsesAllRule()
    {
        var rule = (AllUpdateRule)Parse("""{"all":[{"key":"uA"},{"hashedKey":"uH"}]}""");

        Assert.HasCount(2, rule.Rules);
        Assert.IsInstanceOfType<KeyUpdateRule>(rule.Rules[0]);
        Assert.IsInstanceOfType<HashedKeyUpdateRule>(rule.Rules[1]);
    }


    /// <summary>An <c>atLeast</c> rule parses its threshold and the explicit-and-default weights of its <c>of</c> elements (WP-UR-7).</summary>
    [TestMethod]
    public void ParsesAtLeastRuleWithWeights()
    {
        var rule = (AtLeastUpdateRule)Parse("""{"atLeast":2,"of":[{"weight":2,"key":"uA"},{"key":"uB"}]}""");

        Assert.AreEqual(2, rule.Threshold);
        Assert.HasCount(2, rule.Of);
        Assert.AreEqual(2, rule.Of[0].Weight);
        Assert.AreEqual("uA", ((KeyUpdateRule)rule.Of[0].Rule).MbPubKey);
        Assert.AreEqual(1, rule.Of[1].Weight, "An 'of' element without a 'weight' defaults to weight 1.");
        Assert.AreEqual("uB", ((KeyUpdateRule)rule.Of[1].Rule).MbPubKey);
    }


    /// <summary>Composite rules nest: an <c>any</c> containing an <c>all</c> and a leaf parses to the nested tree.</summary>
    [TestMethod]
    public void ParsesNestedComposite()
    {
        var rule = (AnyUpdateRule)Parse("""{"any":[{"all":[{"key":"uA"},{"key":"uB"}]},{"key":"uC"}]}""");

        Assert.HasCount(2, rule.Rules);
        var inner = (AllUpdateRule)rule.Rules[0];
        Assert.HasCount(2, inner.Rules);
        Assert.AreEqual("uC", ((KeyUpdateRule)rule.Rules[1]).MbPubKey);
    }


    /// <summary>A weighted <c>of</c> element may itself be composite; its weight attaches to the built sub-tree.</summary>
    [TestMethod]
    public void ParsesAtLeastWithCompositeWeightedElement()
    {
        var rule = (AtLeastUpdateRule)Parse("""{"atLeast":3,"of":[{"weight":3,"all":[{"key":"uA"},{"key":"uB"}]}]}""");

        Assert.AreEqual(3, rule.Of[0].Weight);
        Assert.IsInstanceOfType<AllUpdateRule>(rule.Of[0].Rule);
    }


    /// <summary>The parsed tree drives evaluation: an <c>atLeast</c> is satisfied only once the summed weights reach the threshold.</summary>
    [TestMethod]
    public async Task ParsedAtLeastDrivesEvaluation()
    {
        WebPlusUpdateRule rule = Parse("""{"atLeast":2,"of":[{"weight":2,"key":"uA"},{"key":"uB"}]}""");

        Assert.IsTrue(await WebPlusUpdateRuleEvaluation.IsSatisfiedAsync(rule, new HashSet<string> { "uA" }, NoHashedKeyMatch, CancellationToken.None), "The weight-2 key alone meets the threshold of 2.");
        Assert.IsFalse(await WebPlusUpdateRuleEvaluation.IsSatisfiedAsync(rule, new HashSet<string> { "uB" }, NoHashedKeyMatch, CancellationToken.None), "The weight-1 key alone does not meet the threshold of 2.");
        Assert.IsTrue(await WebPlusUpdateRuleEvaluation.IsSatisfiedAsync(rule, new HashSet<string> { "uA", "uB" }, NoHashedKeyMatch, CancellationToken.None), "Both keys together exceed the threshold.");
    }


    /// <summary>A non-string <c>key</c> value is a malformed rule and is rejected.</summary>
    [TestMethod]
    public void RejectsNonStringKey()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"key":123}"""));
    }


    /// <summary>An <c>any</c> whose value is not an array is a malformed rule and is rejected.</summary>
    [TestMethod]
    public void RejectsNonArrayAny()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"any":{}}"""));
    }


    /// <summary>The disallow form is only valid at the top level; a `{}` appearing as a sub-rule is rejected.</summary>
    [TestMethod]
    public void RejectsDisallowAsSubRule()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"any":[{}]}"""));
    }


    /// <summary>A non-integer <c>atLeast</c> threshold is rejected.</summary>
    [TestMethod]
    public void RejectsNonIntegerThreshold()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"atLeast":"two","of":[{"key":"uA"}]}"""));
    }


    /// <summary>An empty <c>all</c> array is rejected: it would otherwise be vacuously satisfied by no proofs.</summary>
    [TestMethod]
    public void RejectsEmptyAllArray()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"all":[]}"""));
    }


    /// <summary>An empty <c>any</c> array is rejected: an empty rule set expresses no authorization policy.</summary>
    [TestMethod]
    public void RejectsEmptyAnyArray()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"any":[]}"""));
    }


    /// <summary>An empty <c>of</c> array in an <c>atLeast</c> rule is rejected.</summary>
    [TestMethod]
    public void RejectsEmptyOfArray()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"atLeast":1,"of":[]}"""));
    }


    /// <summary>A zero <c>atLeast</c> threshold is rejected: it would otherwise be satisfied with no proofs (a keyless takeover of a degenerate rule).</summary>
    [TestMethod]
    public void RejectsZeroAtLeastThreshold()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"atLeast":0,"of":[{"key":"uA"}]}"""));
    }


    /// <summary>A negative <c>atLeast</c> threshold is rejected (a non-positive threshold is satisfied with no proofs).</summary>
    [TestMethod]
    public void RejectsNegativeAtLeastThreshold()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"atLeast":-1,"of":[{"key":"uA"}]}"""));
    }


    /// <summary>A zero <c>weight</c> on an <c>of</c> element is rejected (a non-positive weight is not a meaningful contribution).</summary>
    [TestMethod]
    public void RejectsZeroWeight()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"atLeast":1,"of":[{"weight":0,"key":"uA"}]}"""));
    }


    /// <summary>A negative <c>weight</c> on an <c>of</c> element is rejected.</summary>
    [TestMethod]
    public void RejectsNegativeWeight()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"atLeast":1,"of":[{"weight":-5,"key":"uA"}]}"""));
    }


    /// <summary>
    /// A composite rule object naming more than one shape discriminator is rejected rather than resolved by the
    /// parser's internal precedence: WP-UR-1 fixes a rule as exactly one of the defined forms, so a
    /// <c>{"any":…,"all":…}</c> object is ambiguous.
    /// </summary>
    [TestMethod]
    public void RejectsMultipleDiscriminatorsInComposite()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"any":[{"key":"uA"}],"all":[{"key":"uB"}]}"""));
    }


    /// <summary>A leaf rule object naming both <c>key</c> and <c>hashedKey</c> is ambiguous and rejected (WP-UR-1).</summary>
    [TestMethod]
    public void RejectsMultipleDiscriminatorsInLeaf()
    {
        Assert.ThrowsExactly<JsonException>(() => Parse("""{"key":"uA","hashedKey":"uH"}"""));
    }


    /// <summary>
    /// A DID document that repeats a top-level member is ambiguous and rejected by the strict parser
    /// (<c>AllowDuplicateProperties = false</c>) rather than resolved last-wins — RFC 8785 Section 3.1 leaves JCS
    /// over duplicate keys undefined, and a self-certifying document MUST have one unambiguous byte form.
    /// </summary>
    [TestMethod]
    public void RejectsDuplicateTopLevelDocumentKeys()
    {
        byte[] document = Encoding.UTF8.GetBytes("""{"updateRules":{"key":"uA"},"updateRules":{"key":"uB"}}""");

        Assert.ThrowsExactly<JsonException>(() => Parser(document));
    }
}
