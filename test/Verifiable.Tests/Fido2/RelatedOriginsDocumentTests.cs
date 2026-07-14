using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for the model-only, relying-party-hostable half of
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">W3C Web Authentication Level 3,
/// section 5.11: Using Web Authentication across related origins</see>: <see cref="RelatedOrigins.IsValidOrigin"/>,
/// <see cref="RelatedOrigins.HasSingleCommonRpId"/>, and <see cref="WellKnownWebAuthnValues.RelatedOriginsWellKnownPath"/>.
/// JSON reader/writer coverage lives in <c>RelatedOriginsJsonTests</c>.
/// </summary>
[TestClass]
internal sealed class RelatedOriginsDocumentTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>Structurally valid HTTPS origins <see cref="RelatedOrigins.IsValidOrigin"/> MUST accept.</summary>
    public static IEnumerable<object[]> ValidOriginCases =>
    [
        ["PlainHost", "https://example.com"],
        ["ExplicitDefaultPort", "https://example.com:443"],
        ["ExplicitNonDefaultPort", "https://example.com:8443"],
        ["UppercaseHost", "https://EXAMPLE.COM"],
        ["PunycodeHost", "https://xn--caf-dma.example"],
        ["ExplicitRootPath", "https://example.com/"],
        ["CrWorkedExampleEntry", "https://exampledelivery.co.uk"]
    ];


    /// <summary>Strings <see cref="RelatedOrigins.IsValidOrigin"/> MUST reject.</summary>
    public static IEnumerable<object[]> InvalidOriginCases =>
    [
        ["HttpScheme", "http://example.com"],
        ["PathBeyondRoot", "https://example.com/x"],
        ["Query", "https://example.com?x=1"],
        ["Fragment", "https://example.com#frag"],
        ["Userinfo", "https://user:pass@example.com"],
        ["BareHostWithoutScheme", "example.com"],
        ["RelativeStringCrossPlatformFileTrap", "/relative"],
        ["EmptyString", ""],
        ["WhitespaceOnly", "   "]
    ];


    /// <summary>Each structurally valid HTTPS origin is accepted.</summary>
    [TestMethod]
    [DynamicData(nameof(ValidOriginCases))]
    public void StructurallyValidHttpsOriginIsAccepted(string caseName, string candidate)
    {
        Assert.IsTrue(RelatedOrigins.IsValidOrigin(candidate), caseName);
    }


    /// <summary>
    /// Each structurally invalid candidate is rejected, including the cross-platform trap case where a
    /// bare, scheme-less string can parse as an absolute <c>file:</c> URI on some platforms — the explicit
    /// <c>https:</c> scheme check rejects it regardless.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(InvalidOriginCases))]
    public void StructurallyInvalidCandidateIsRejected(string caseName, string candidate)
    {
        Assert.IsFalse(RelatedOrigins.IsValidOrigin(candidate), caseName);
    }


    /// <summary>A <see langword="null"/> candidate is rejected with <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public void NullCandidateThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => RelatedOrigins.IsValidOrigin(null!));
    }


    /// <summary>A single RP ID trivially satisfies the common-RP-ID requirement.</summary>
    [TestMethod]
    public void SingleRpIdIsACommonRpId()
    {
        Assert.IsTrue(RelatedOrigins.HasSingleCommonRpId(["example.com"]));
    }


    /// <summary>The same RP ID repeated across every ceremony still satisfies the common-RP-ID requirement.</summary>
    [TestMethod]
    public void RepeatedIdenticalRpIdIsACommonRpId()
    {
        Assert.IsTrue(RelatedOrigins.HasSingleCommonRpId(["example.com", "example.com", "example.com"]));
    }


    /// <summary>
    /// Two distinct RP IDs violate section 5.11's "Such Relying Parties MUST choose a common RP ID to use
    /// across all ceremonies from related origins."
    /// </summary>
    [TestMethod]
    public void TwoDistinctRpIdsAreNotACommonRpId()
    {
        Assert.IsFalse(RelatedOrigins.HasSingleCommonRpId(["example.com", "example.co.uk"]));
    }


    /// <summary>An empty RP ID sequence names no common RP ID.</summary>
    [TestMethod]
    public void EmptyRpIdSequenceIsNotACommonRpId()
    {
        Assert.IsFalse(RelatedOrigins.HasSingleCommonRpId([]));
    }


    /// <summary>A <see langword="null"/> RP ID sequence is rejected with <see cref="ArgumentNullException"/>.</summary>
    [TestMethod]
    public void NullRpIdSequenceThrowsArgumentNullException()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => RelatedOrigins.HasSingleCommonRpId(null!));
    }


    /// <summary>
    /// The well-known path constant matches section 5.11.1's exact URL construction
    /// (<c>https://&lt;rpId&gt;/.well-known/webauthn</c>).
    /// </summary>
    [TestMethod]
    public void RelatedOriginsWellKnownPathHasTheExactSpecifiedValue()
    {
        Assert.AreEqual("/.well-known/webauthn", WellKnownWebAuthnValues.RelatedOriginsWellKnownPath);
    }
}
