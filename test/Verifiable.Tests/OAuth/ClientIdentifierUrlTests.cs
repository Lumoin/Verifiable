using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Vector-table coverage for <see cref="ClientIdentifierUrl"/> against
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html#section-3">
/// draft-ietf-oauth-client-id-metadata-document-02 Section 3</see>. Every CIMD-001..011 row gets at least
/// one accepting and one rejecting/flagging vector; CIMD-008/CIMD-016 (RFC 3986 §6.2.1 simple string
/// comparison) get their own ordinal-comparison vectors. CIMD-009/CIMD-010 (short/stable URL RECOMMENDED)
/// have no machine-checkable shape and are covered only by the doc-comment guidance on
/// <see cref="ClientIdentifierUrl"/> itself — no test represents them.
/// </summary>
[TestClass]
internal sealed class ClientIdentifierUrlTests
{
    [TestMethod]
    //Baseline: every Section 3 MUST/MUST NOT rule satisfied.
    [DataRow("https://example.com/client", true)]
    [DataRow("https://example.com/path/to/client", true)]

    //CIMD-003: a port MAY be present, default or otherwise, without becoming a defect.
    [DataRow("https://example.com:8443/client", true)]
    [DataRow("https://example.com:443/client", true)]

    //CIMD-011: a root path is valid; the NOT RECOMMENDED guidance is advisory only.
    [DataRow("https://example.com/", true)]

    //CIMD-006: a query component is valid; the SHOULD NOT guidance is advisory only.
    [DataRow("https://example.com/client?q=1", true)]
    [DataRow("https://example.com/client?", true)]

    //CIMD-001: the https scheme is required; scheme comparison itself is case-insensitive (RFC 3986 §3.1).
    [DataRow("http://example.com/client", false)]
    [DataRow("HTTPS://example.com/client", true)]

    //CIMD-002: no userinfo component, with or without a password subcomponent.
    [DataRow("https://user@example.com/client", false)]
    [DataRow("https://user:pass@example.com/client", false)]

    //CIMD-004: a path component is required — an authority-only URL fails.
    [DataRow("https://example.com", false)]

    //CIMD-005: no single-dot or double-dot path segment, wherever it appears.
    [DataRow("https://example.com/./client", false)]
    [DataRow("https://example.com/../client", false)]
    [DataRow("https://example.com/a/../b", false)]
    [DataRow("https://example.com/a/./b", false)]
    [DataRow("https://example.com/..", false)]
    [DataRow("https://example.com/a..b/c", true)]

    //CIMD-007: no fragment component.
    [DataRow("https://example.com/client#frag", false)]
    [DataRow("https://example.com/client?q=1#frag", false)]

    //Not even an absolute https URL: no MUST/MUST NOT-tier flag other than NotAnAbsoluteUrl applies.
    [DataRow("", false)]
    [DataRow("not-a-url", false)]
    [DataRow("https:example.com/client", false)]
    [DataRow("//example.com/client", false)]
    [DataRow("://example.com/client", false)]
    public void ValidateProducesTheExpectedIsValidAcrossTheVectorTable(string candidate, bool expectedIsValid)
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate(candidate);

        Assert.AreEqual(expectedIsValid, result.IsValid, candidate);
    }


    /// <summary>CIMD-001: the https scheme is accepted with no scheme-related defect.</summary>
    [TestMethod]
    public void HttpsSchemeIsAccepted()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client");

        Assert.IsFalse(result.NotHttpsScheme);
        Assert.IsTrue(result.IsValid);
    }


    /// <summary>CIMD-001: a non-https scheme is flagged and fails the MUST-tier aggregate.</summary>
    [TestMethod]
    public void NonHttpsSchemeIsRejected()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("http://example.com/client");

        Assert.IsTrue(result.NotHttpsScheme);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>CIMD-002: no userinfo component is accepted with no userinfo defect.</summary>
    [TestMethod]
    public void AbsentUserinfoIsAccepted()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client");

        Assert.IsFalse(result.HasUserinfo);
        Assert.IsTrue(result.IsValid);
    }


    /// <summary>CIMD-002: a userinfo component is flagged and fails the MUST-tier aggregate.</summary>
    [TestMethod]
    public void PresentUserinfoIsRejected()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://user@example.com/client");

        Assert.IsTrue(result.HasUserinfo);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>CIMD-003: a port, default or otherwise, is accepted — MAY never becomes a defect.</summary>
    [TestMethod]
    public void PortIsAcceptedWithAndWithoutAnExplicitValue()
    {
        ClientIdentifierUrlValidationResult withPort = ClientIdentifierUrl.Validate("https://example.com:8443/client");
        ClientIdentifierUrlValidationResult withoutPort = ClientIdentifierUrl.Validate("https://example.com/client");

        Assert.IsTrue(withPort.IsValid);
        Assert.IsTrue(withoutPort.IsValid);
    }


    /// <summary>CIMD-004: a non-empty path is accepted with no missing-path defect.</summary>
    [TestMethod]
    public void PresentPathIsAccepted()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client");

        Assert.IsFalse(result.MissingPathComponent);
        Assert.IsTrue(result.IsValid);
    }


    /// <summary>CIMD-004: an authority-only URL — no path at all — is flagged and rejected.</summary>
    [TestMethod]
    public void AbsentPathIsRejected()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com");

        Assert.IsTrue(result.MissingPathComponent);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>CIMD-005: a path with no dot segment is accepted with no dot-segment defect.</summary>
    [TestMethod]
    public void PathWithoutDotSegmentsIsAccepted()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client");

        Assert.IsFalse(result.HasDotSegments);
        Assert.IsTrue(result.IsValid);
    }


    /// <summary>CIMD-005: a single-dot path segment is flagged and rejected.</summary>
    [TestMethod]
    public void SingleDotSegmentIsRejected()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/./client");

        Assert.IsTrue(result.HasDotSegments);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>CIMD-005: a double-dot path segment is flagged and rejected.</summary>
    [TestMethod]
    public void DoubleDotSegmentIsRejected()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/../client");

        Assert.IsTrue(result.HasDotSegments);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// CIMD-005 negative control: a segment that merely contains dots, such as <c>a..b</c>, is not a
    /// dot segment — only a segment that IS exactly <c>.</c> or <c>..</c> counts.
    /// </summary>
    [TestMethod]
    public void SegmentContainingDotsWithoutBeingADotSegmentIsAccepted()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/a..b/c");

        Assert.IsFalse(result.HasDotSegments);
        Assert.IsTrue(result.IsValid);
    }


    /// <summary>CIMD-006: the query component is absent; the advisory flag stays clear.</summary>
    [TestMethod]
    public void AbsentQueryHasNoAdvisory()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client");

        Assert.IsFalse(result.HasQueryComponent);
    }


    /// <summary>CIMD-006: a query component is SHOULD NOT-tier — flagged, but does not fail <see cref="ClientIdentifierUrlValidationResult.IsValid"/>.</summary>
    [TestMethod]
    public void PresentQueryIsAdvisoryOnlyAndStaysValid()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client?q=1");

        Assert.IsTrue(result.HasQueryComponent);
        Assert.IsTrue(result.IsValid);
    }


    /// <summary>CIMD-007: no fragment component is accepted with no fragment defect.</summary>
    [TestMethod]
    public void AbsentFragmentIsAccepted()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client");

        Assert.IsFalse(result.HasFragment);
        Assert.IsTrue(result.IsValid);
    }


    /// <summary>CIMD-007: a fragment component is flagged and fails the MUST-tier aggregate.</summary>
    [TestMethod]
    public void PresentFragmentIsRejected()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client#frag");

        Assert.IsTrue(result.HasFragment);
        Assert.IsFalse(result.IsValid);
    }


    /// <summary>CIMD-011: a path of exactly <c>/</c> is valid; the NOT RECOMMENDED guidance is advisory only.</summary>
    [TestMethod]
    public void RootPathIsValidWithTheAdvisoryFlagSet()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/");

        Assert.IsTrue(result.IsRootPath);
        Assert.IsFalse(result.MissingPathComponent);
        Assert.IsTrue(result.IsValid);
    }


    /// <summary>CIMD-011 negative control: a non-root path never sets the root-path advisory.</summary>
    [TestMethod]
    public void NonRootPathHasNoRootAdvisory()
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate("https://example.com/client");

        Assert.IsFalse(result.IsRootPath);
    }


    /// <summary>
    /// A candidate lacking the <c>scheme://authority/path</c> shape entirely is flagged
    /// <see cref="ClientIdentifierUrlValidationResult.NotAnAbsoluteUrl"/>, with every other defect flag
    /// left at its default since there is no authority or path to inspect.
    /// </summary>
    [TestMethod]
    [DataRow("")]
    [DataRow("not-a-url")]
    [DataRow("https:example.com/client")]
    [DataRow("//example.com/client")]
    public void CandidateWithoutAbsoluteUrlShapeIsRejected(string candidate)
    {
        ClientIdentifierUrlValidationResult result = ClientIdentifierUrl.Validate(candidate);

        Assert.IsTrue(result.NotAnAbsoluteUrl);
        Assert.IsFalse(result.IsValid);
        Assert.IsFalse(result.NotHttpsScheme);
        Assert.IsFalse(result.HasUserinfo);
        Assert.IsFalse(result.MissingPathComponent);
        Assert.IsFalse(result.HasDotSegments);
        Assert.IsFalse(result.HasFragment);
    }


    /// <summary>
    /// CIMD-008: identical Client Identifier URL strings match — the positive control for
    /// <see cref="ClientIdentifierUrl.IsMatch"/>.
    /// </summary>
    [TestMethod]
    public void IsMatchAcceptsIdenticalStrings()
    {
        Assert.IsTrue(ClientIdentifierUrl.IsMatch("https://example.com/client", "https://example.com/client"));
    }


    /// <summary>
    /// CIMD-008: the spec's own non-equivalence example — a default-port URL and its portless
    /// equivalent are NOT the same Client Identifier URL under simple string comparison, even though
    /// 443 is the https default port.
    /// </summary>
    [TestMethod]
    public void IsMatchRejectsDefaultPortElision()
    {
        Assert.IsFalse(ClientIdentifierUrl.IsMatch("https://example.com/client", "https://example.com:443/client"));
    }


    /// <summary>CIMD-008: a trailing-slash variant is a different string under ordinal comparison.</summary>
    [TestMethod]
    public void IsMatchRejectsTrailingSlashVariant()
    {
        Assert.IsFalse(ClientIdentifierUrl.IsMatch("https://example.com/client", "https://example.com/client/"));
    }


    /// <summary>
    /// CIMD-008: percent-encoding hex-digit case is not folded — <c>%2F</c> and <c>%2f</c> encode the
    /// same octet but are different strings under simple string comparison.
    /// </summary>
    [TestMethod]
    public void IsMatchRejectsPercentEncodingCaseVariant()
    {
        Assert.IsFalse(ClientIdentifierUrl.IsMatch("https://example.com/a%2Fb", "https://example.com/a%2fb"));
    }


    /// <summary>
    /// CIMD-016 reuses the same simple-string-comparison rule to match a fetched document's
    /// <c>client_id</c> value against the URL used to fetch it; scheme-case is not folded here either,
    /// since <see cref="ClientIdentifierUrl.IsMatch"/> is the whole-string ordinal comparison, distinct
    /// from <see cref="ClientIdentifierUrl.Validate"/>'s case-insensitive scheme check.
    /// </summary>
    [TestMethod]
    public void IsMatchRejectsSchemeCaseVariant()
    {
        Assert.IsFalse(ClientIdentifierUrl.IsMatch("https://example.com/client", "HTTPS://example.com/client"));
    }
}
