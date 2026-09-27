using System.Text;

namespace Verifiable.Tests.Core;

/// <summary>
/// Catalog tests for <see cref="WellKnownProblemTypes"/>.
/// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
/// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
/// The rate-limit names are proposed registrations in draft-ietf-httpapi-ratelimit-headers-11.
/// </summary>
[TestClass]
internal sealed class WellKnownProblemTypesTests
{
    /// <summary>
    /// Literal URI spellings paired with <see cref="WellKnownProblemTypes"/> values.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4.2.1">RFC 9457 §4.2.1</see>:
    /// "Type URI: about:blank". The other spellings come from the proposed registrations in
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-10.2">RateLimit draft-11 §10.2</see>:
    /// "IANA is asked to register the following entries in the "HTTP Problem Types" registry".
    /// </summary>
    public static IEnumerable<object[]> GetProblemTypeSpellings()
    {
        yield return new object[] { "about:blank", WellKnownProblemTypes.AboutBlank };
        yield return new object[] { "https://iana.org/assignments/http-problem-types#quota-exceeded", WellKnownProblemTypes.QuotaExceeded };
        yield return new object[] { "https://iana.org/assignments/http-problem-types#temporary-reduced-capacity", WellKnownProblemTypes.TemporaryReducedCapacity };
        yield return new object[] { "https://iana.org/assignments/http-problem-types#abnormal-usage-detected", WellKnownProblemTypes.AbnormalUsageDetected };
    }


    /// <summary>
    /// Literal identifiers paired with the recognition predicates of <see cref="WellKnownProblemTypes"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
    /// </summary>
    public static IEnumerable<object[]> GetProblemTypePredicates()
    {
        yield return new object[] { "about:blank", new Func<string, bool>(WellKnownProblemTypes.IsAboutBlank) };
        yield return new object[] { "https://iana.org/assignments/http-problem-types#quota-exceeded", new Func<string, bool>(WellKnownProblemTypes.IsQuotaExceeded) };
        yield return new object[] { "https://iana.org/assignments/http-problem-types#temporary-reduced-capacity", new Func<string, bool>(WellKnownProblemTypes.IsTemporaryReducedCapacity) };
        yield return new object[] { "https://iana.org/assignments/http-problem-types#abnormal-usage-detected", new Func<string, bool>(WellKnownProblemTypes.IsAbnormalUsageDetected) };
    }


    /// <summary>
    /// Each catalog value spells its defining identifier literally.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-4.2.1">RFC 9457 §4.2.1</see>:
    /// "Type URI: about:blank".
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.1">RateLimit draft-11 §5.1</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#quota-exceeded" problem type."
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.2">§5.2</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#temporary-reduced-capacity" problem type."
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-11.html#section-5.3">§5.3</see>:
    /// "This section defines the "https://iana.org/assignments/http-problem-types#abnormal-usage-detected" problem type."
    /// The three draft registrations are proposed.
    /// </summary>
    /// <param name="expected">The independently transcribed URI.</param>
    /// <param name="tabledValue">The catalog value under test.</param>
    [TestMethod]
    [DynamicData(nameof(GetProblemTypeSpellings))]
    public void EveryProblemTypeSpellsItsDefiningUri(string expected, string tabledValue)
    {
        Assert.AreEqual(expected, tabledValue);
    }


    /// <summary>
    /// The local UTF-8 twin rule keeps both representations of <see cref="WellKnownProblemTypes"/> identical.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
    /// </summary>
    [TestMethod]
    public void EveryProblemTypeHasAUtf8TwinHoldingTheSameBytes()
    {
        Assert.AreEqual(WellKnownProblemTypes.AboutBlank, Encoding.UTF8.GetString(WellKnownProblemTypes.AboutBlankUtf8));
        Assert.AreEqual(WellKnownProblemTypes.QuotaExceeded, Encoding.UTF8.GetString(WellKnownProblemTypes.QuotaExceededUtf8));
        Assert.AreEqual(WellKnownProblemTypes.TemporaryReducedCapacity, Encoding.UTF8.GetString(WellKnownProblemTypes.TemporaryReducedCapacityUtf8));
        Assert.AreEqual(WellKnownProblemTypes.AbnormalUsageDetected, Encoding.UTF8.GetString(WellKnownProblemTypes.AbnormalUsageDetectedUtf8));
    }


    /// <summary>
    /// Each predicate recognizes an independently allocated spelling of its identifier.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
    /// This is a local catalog comparison rule.
    /// </summary>
    /// <param name="wireValue">The literal identifier.</param>
    /// <param name="isProblemType">The identifier's recognition predicate.</param>
    [TestMethod]
    [DynamicData(nameof(GetProblemTypePredicates))]
    public void EveryPredicateRecognizesItsOwnUri(string wireValue, Func<string, bool> isProblemType)
    {
        Assert.IsTrue(isProblemType(new string(wireValue.ToCharArray())));
    }


    /// <summary>
    /// Each predicate distinguishes its identifier from every other catalog entry.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
    /// This is a local catalog comparison rule.
    /// </summary>
    /// <param name="wireValue">The predicate's own identifier.</param>
    /// <param name="isProblemType">The identifier's recognition predicate.</param>
    [TestMethod]
    [DynamicData(nameof(GetProblemTypePredicates))]
    public void EveryPredicateRejectsOtherProblemTypes(string wireValue, Func<string, bool> isProblemType)
    {
        foreach(object[] spelling in GetProblemTypeSpellings())
        {
            string other = (string)spelling[0];
            if(!string.Equals(wireValue, other, StringComparison.Ordinal))
            {
                Assert.IsFalse(isProblemType(other));
            }

        }

    }


    /// <summary>
    /// An equal URI selects the interned catalog instance under the local storage rule.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
    /// </summary>
    /// <param name="expected">The independently transcribed identifier.</param>
    /// <param name="tabledValue">The interned catalog instance.</param>
    [TestMethod]
    [DynamicData(nameof(GetProblemTypeSpellings))]
    public void CanonicalizationReturnsTheInternedProblemType(string expected, string tabledValue)
    {
        string received = new(expected.ToCharArray());

        Assert.AreSame(tabledValue, WellKnownProblemTypes.GetCanonicalizedValue(received));
        Assert.AreSame(tabledValue, string.IsInterned(tabledValue));
    }


    /// <summary>
    /// A URI outside the catalog is preserved by the local canonicalization rule.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "The "type" member is a JSON string containing a URI reference [URI] that identifies the problem type."
    /// </summary>
    [TestMethod]
    public void CanonicalizationPreservesAnUnknownProblemType()
    {
        string unknown = new("https://example.com/problems/custom".ToCharArray());

        Assert.AreSame(unknown, WellKnownProblemTypes.GetCanonicalizedValue(unknown));
    }


    /// <summary>
    /// The catalog's local ordinal policy distinguishes different URI fragment spellings.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9457#section-3.1.1">RFC 9457 §3.1.1</see>:
    /// "Consumers MUST use the "type" URI (after resolution, if necessary) as the problem type's primary identifier."
    /// The RFC identifies the URI's role; ordinal comparison is the catalog's chosen policy.
    /// </summary>
    /// <param name="valueA">The first spelling.</param>
    /// <param name="valueB">The second spelling.</param>
    /// <param name="isExpectedEqual">Whether the spellings are ordinally equal.</param>
    [TestMethod]
    [DataRow("https://iana.org/assignments/http-problem-types#quota-exceeded", "https://iana.org/assignments/http-problem-types#quota-exceeded", true)]
    [DataRow("https://iana.org/assignments/http-problem-types#quota-exceeded", "https://iana.org/assignments/http-problem-types#Quota-exceeded", false)]
    public void ProblemTypeUrisCompareOrdinally(string valueA, string valueB, bool isExpectedEqual)
    {
        Assert.AreEqual(isExpectedEqual, WellKnownProblemTypes.Equals(valueA, valueB));
    }
}
