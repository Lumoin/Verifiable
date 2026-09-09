using System;
using System.Text;
using Verifiable.Core.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusClaimReader"/>, the span reader for a JOSE Referenced Token's
/// <c>status</c> claim — the mechanisms it names and the <c>status_list</c> reference it may carry.
/// Every input here is hand-written against the Section 6.1/6.2 claim rules and Section 6.2's
/// non-normative example — none is produced by a converter or a composition, so the reader is
/// measured against the specification text rather than against a sibling writer's output.
/// </summary>
/// <remarks>
/// <para>
/// The reader answers three ways, and every test below pins one of them: the claim is unreadable
/// (<see langword="false"/>), the claim names only mechanisms this library does not evaluate
/// (<see langword="true"/> with <see cref="StatusClaim.StatusList"/> <see langword="null"/>), or the
/// claim carries a reference a verifier can resolve. A caller whose token has no <c>status</c> claim
/// at all never reaches the reader, which is the fourth state and is not this type's to report.
/// </para>
/// <para>
/// The SD-JWT VC verifier seat reads a presented credential's reference through this same reader;
/// that end-to-end surfacing is proved once, by
/// <see cref="Verifiable.Tests.OAuth.Oid4VpFlowIntegrationTests.SdJwtVcStatusReferenceSurfacesAndDrivesRevocationGate"/>,
/// and is deliberately not repeated here.
/// </para>
/// </remarks>
[TestClass]
internal sealed class StatusClaimReaderTests
{
    /// <summary>
    /// The Section 6.2 non-normative example's <c>status</c> claim object, verbatim from the decoded
    /// payload the specification prints, whitespace collapsed.
    /// </summary>
    private const string SectionExampleStatusObject =
        /*lang=json,strict*/ """{"status_list":{"idx":0,"uri":"https://example.com/statuslists/1"}}""";

    /// <summary>
    /// The <c>uri</c> the Section 6.2 example carries.
    /// </summary>
    private const string SectionExampleUri = "https://example.com/statuslists/1";

    /// <summary>
    /// A mechanism name no specification defines, used where the point is that the reader records a
    /// name it has no model for rather than the specific mechanism named.
    /// </summary>
    private const string UnmodelledMechanism = "other_mechanism";

    /// <summary>
    /// Gets or sets the context information for the current test run.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST
    /// specify a JSON Object that contains a reference to a Status List Token. It MUST at least
    /// contain the following claims: idx: REQUIRED. The idx (index) claim MUST specify a non-negative
    /// Integer that represents the index to check for status information in the Status List for the
    /// current Referenced Token. uri: REQUIRED. The uri (URI) claim MUST specify a String value that
    /// identifies the Status List Token containing the status information for the Referenced Token.
    /// The value of uri MUST be a URI conforming to [RFC3986]."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// The Section 6.2 example carries <c>idx</c> 0 — the lower edge of "non-negative", and the value
    /// an off-by-one reading of "non-negative" would wrongly refuse.
    /// </summary>
    [TestMethod]
    public void TheSectionExampleStatusClaimYieldsItsIndexAndUri()
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(SectionExampleStatusObject);

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsTrue(isRead, "A status claim carrying a status_list object with idx and uri is a well-formed reference.");
        Assert.AreEqual(0, claim!.StatusList!.Value.Index, "idx 0 is a non-negative Integer and is the index the example specifies.");
        Assert.AreEqual(SectionExampleUri, claim.StatusList!.Value.Uri, "uri is the string value identifying the Status List Token.");
        Assert.HasCount(1, claim.Mechanisms, "The example's status object names exactly one status mechanism.");
        Assert.Contains(StatusMechanismNames.StatusList, claim.Mechanisms, "The named mechanism is status_list.");
    }


    /// <summary>
    /// "idx: REQUIRED. The idx (index) claim MUST specify a non-negative Integer that represents the
    /// index to check for status information in the Status List for the current Referenced Token."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// An index beyond the first entry is read as the integer it is, not truncated or re-based.
    /// </summary>
    [TestMethod]
    public void ANonZeroIndexIsReadAsTheIntegerItIs()
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """{"status_list":{"idx":2147483647,"uri":"https://example.com/statuslists/1"}}""");

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsTrue(isRead, "The largest index a status list entry can be addressed by is a non-negative Integer.");
        Assert.AreEqual(int.MaxValue, claim!.StatusList!.Value.Index, "The index is carried through exactly as written.");
    }


    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used. … It
    /// MUST at least contain the following claims" — "at least" is the licence for further members,
    /// and Section 6.2 closes with "Application of additional restrictions and policies are at the
    /// discretion of the Relying Party."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// Members beyond <c>idx</c> and <c>uri</c> inside the <c>status_list</c> object therefore never
    /// displace or invalidate the reference.
    /// </summary>
    [TestMethod]
    public void MembersBeyondTheRequiredOnesInsideTheReferenceAreTolerated()
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """
            {"status_list":{"note":"issued in batch 7","idx":42,"uri":"https://example.com/statuslists/1","aggregation_uri":"https://example.com/aggregation"}}
            """);

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsTrue(isRead, "A status_list object carrying more than idx and uri still contains the required reference.");
        Assert.AreEqual(42, claim!.StatusList!.Value.Index, "Additional members must not displace the idx that is read.");
        Assert.AreEqual(SectionExampleUri, claim.StatusList!.Value.Uri, "Additional members must not displace the uri that is read.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// "at least one" licenses more than one: every top-level member of the object is a mechanism the
    /// issuer named, so a claim naming <c>status_list</c> beside another mechanism records both names
    /// and still yields the reference the modelled one carries.
    /// </summary>
    [TestMethod]
    public void AClaimNamingASecondMechanismBesideStatusListRecordsBothAndReadsTheReference()
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """
            {"identifier_list":{"id":"6fc2-a3b1","uri":"https://example.com/identifierlists/1"},"status_list":{"idx":0,"uri":"https://example.com/statuslists/1"}}
            """);

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsTrue(isRead, "An object naming two status mechanisms satisfies Section 6.1's at-least-one requirement.");
        Assert.HasCount(2, claim!.Mechanisms, "Both top-level members are status mechanisms the issuer named.");
        Assert.Contains(StatusMechanismNames.StatusList, claim.Mechanisms, "status_list is one of the two mechanisms named.");
        Assert.Contains(StatusMechanismNames.IdentifierList, claim.Mechanisms, "The second mechanism must reach the caller by name.");
        Assert.AreEqual(0, claim.StatusList!.Value.Index, "The status_list member's idx is read even beside a mechanism this library does not model.");
        Assert.AreEqual(SectionExampleUri, claim.StatusList!.Value.Uri, "The status_list member's uri is read even beside a mechanism this library does not model.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// <c>status_list</c> is one status mechanism among others: a claim naming a different mechanism
    /// satisfies Section 6.1 and is read, carrying that mechanism's name with no reference. That is a
    /// different answer from an unreadable claim, and a different answer again from a token with no
    /// <c>status</c> claim at all — collapsing the three would make a credential whose issuer gated
    /// its validity on a mechanism this library does not evaluate look unconditioned.
    /// </summary>
    [TestMethod]
    public void AClaimNamingOnlyTheIdentifierListMechanismIsReadWithNoReference()
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """{"identifier_list":{"id":"6fc2-a3b1","uri":"https://example.com/identifierlists/1"}}""");

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsTrue(isRead, "The object contains one reference to a status mechanism, which is what Section 6.1 requires.");
        Assert.IsNull(claim!.StatusList, "The claim names no status_list mechanism, so there is no reference to read.");
        Assert.HasCount(1, claim.Mechanisms, "Exactly the one mechanism the object named is recorded.");
        Assert.Contains(StatusMechanismNames.IdentifierList, claim.Mechanisms, "The mechanism the issuer named must reach the caller by name.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// An object present but empty names no mechanism at all: it is not the absence of a
    /// <c>status</c> claim, it is a <c>status</c> claim that fails the requirement, so the reader
    /// refuses it rather than reporting a claim naming nothing.
    /// </summary>
    [TestMethod]
    public void AStatusObjectWithNoMemberIsRefused()
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(/*lang=json,strict*/ """{}""");

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsFalse(isRead, "An object with no member contains no reference to a status mechanism, which Section 6.1 requires.");
        Assert.IsNull(claim, "A refused read leaves the claim null, never a claim naming nothing.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// A member name that repeats leaves "which mechanism did the issuer name" answerable two ways, so
    /// a producer could show one reader a resolvable reference and another reader a different one. The
    /// claim is refused outright rather than resolved by a first-wins or last-wins rule neither the
    /// specification nor RFC 8259 fixes.
    /// </summary>
    [TestMethod]
    public void ARepeatedTopLevelMechanismNameIsRefused()
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(
            /*lang=json*/ """
            {"status_list":{"idx":0,"uri":"https://example.com/statuslists/1"},"status_list":{"idx":9,"uri":"https://example.com/statuslists/2"}}
            """);

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsFalse(isRead, "A repeated mechanism name makes the issuer's statement ambiguous, so no claim can be read from it.");
        Assert.IsNull(claim, "A refused read leaves the claim null, never one of the two candidate readings.");
    }


    /// <summary>
    /// "The status (status) claim MUST specify a JSON Object that contains at least one reference to a
    /// status mechanism." / "status_list: REQUIRED when the status mechanism defined in this
    /// specification is used."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>.
    /// The mechanisms are the object's own members, so a <c>status_list</c> object appearing inside
    /// another mechanism's value belongs to that mechanism's contents and is not the claim's
    /// reference. Reading it would let a mechanism this library does not model smuggle in a reference
    /// the issuer never stated at the claim's own level.
    /// </summary>
    [TestMethod]
    public void AStatusListNestedInsideAnotherMechanismsValueIsNotTheClaimsReference()
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(
            /*lang=json,strict*/ """
            {"other_mechanism":{"status_list":{"idx":7,"uri":"https://example.com/statuslists/9"}}}
            """);

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsTrue(isRead, "The object names one status mechanism at its own level, which Section 6.1 requires.");
        Assert.HasCount(1, claim!.Mechanisms, "Only the top-level member is a status mechanism.");
        Assert.Contains(UnmodelledMechanism, claim.Mechanisms, "The mechanism the issuer named at the claim's own level is the one recorded.");
        Assert.DoesNotContain(StatusMechanismNames.StatusList, claim.Mechanisms, "A nested status_list is another mechanism's content, not a mechanism the claim names.");
        Assert.IsNull(claim.StatusList, "A nested status_list must never be read as the claim's own reference.");
    }


    /// <summary>
    /// "The status (status) claim MUST specify a JSON Object that contains at least one reference to a
    /// status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status List, Section 6.1</see>,
    /// over the JSON grammar of <see href="https://www.rfc-editor.org/rfc/rfc8259#section-2">RFC 8259, Section 2</see>:
    /// "Insignificant whitespace is allowed before or after any of the six structural characters."
    /// An issuer serializing its payload with whitespace states the same claim as one serializing it
    /// compactly, so the reader must answer identically for both.
    /// </summary>
    [TestMethod]
    public void InsignificantWhitespaceDoesNotChangeWhatIsRead()
    {
        byte[] compact = Encoding.UTF8.GetBytes(SectionExampleStatusObject);
        byte[] spaced = Encoding.UTF8.GetBytes(
            "{\n  \"status_list\" : {\n    \"idx\" : 0 ,\n    \"uri\" : \"https://example.com/statuslists/1\"\n  }\n}");

        bool isCompactRead = StatusClaimReader.TryRead(compact, out StatusClaim? fromCompact);
        bool isSpacedRead = StatusClaimReader.TryRead(spaced, out StatusClaim? fromSpaced);

        Assert.IsTrue(isCompactRead, "The compactly serialized claim is well-formed.");
        Assert.IsTrue(isSpacedRead, "Whitespace between structural characters is insignificant, so the same claim must still be readable.");
        Assert.AreEqual(fromCompact, fromSpaced, "Two serializations of one claim must read as the same claim.");
    }


    /// <summary>
    /// "status_list: REQUIRED when the status mechanism defined in this specification is used. It MUST
    /// specify a JSON Object that contains a reference to a Status List Token. It MUST at least
    /// contain the following claims: idx: REQUIRED. The idx (index) claim MUST specify a non-negative
    /// Integer … uri: REQUIRED. The uri (URI) claim MUST specify a String value … The value of uri
    /// MUST be a URI conforming to [RFC3986]."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// Every one of these requirements is violated by an input a holder can present, so the reader
    /// answers each with a plain "no claim here" and never a thrown exception — a status claim is
    /// attacker-controlled data read before any status statement exists. A named <c>status_list</c>
    /// that does not conform makes the whole claim unreadable rather than degrading it to a claim
    /// naming an unevaluable mechanism, which would turn a malformed reference into a policy decision.
    /// </summary>
    /// <param name="statusObjectJson">The malformed or incomplete <c>status</c> claim object.</param>
    /// <param name="violatedRequirement">The Section 6.2 requirement the input violates.</param>
    [TestMethod]
    [DataRow("""{"status_list":{"uri":"https://example.com/statuslists/1"}}""", "idx is REQUIRED")]
    [DataRow("""{"status_list":{"idx":0}}""", "uri is REQUIRED")]
    [DataRow("""{"status_list":{}}""", "idx and uri are both REQUIRED")]
    [DataRow("""{"status_list":{"idx":-1,"uri":"https://example.com/statuslists/1"}}""", "idx MUST specify a non-negative Integer")]
    [DataRow("""{"status_list":{"idx":2147483648,"uri":"https://example.com/statuslists/1"}}""", "idx MUST address an entry of a Status List")]
    [DataRow("""{"status_list":{"idx":1.5,"uri":"https://example.com/statuslists/1"}}""", "idx MUST specify an Integer")]
    [DataRow("""{"status_list":{"idx":"0","uri":"https://example.com/statuslists/1"}}""", "idx MUST specify an Integer, not a String")]
    [DataRow("""{"status_list":{"idx":0,"uri":"/statuslists/1"}}""", "uri MUST be a URI conforming to RFC 3986, not a relative reference")]
    [DataRow("""{"status_list":{"idx":0,"uri":"example.com/statuslists/1"}}""", "uri MUST be a URI conforming to RFC 3986, which carries a scheme")]
    [DataRow("""{"status_list":{"idx":0,"uri":""}}""", "uri MUST specify a String value identifying the Status List Token")]
    [DataRow("""{"status_list":{"idx":0,"uri":" "}}""", "uri MUST specify a String value, and a space names no Status List Token")]
    [DataRow("""{"status_list":{"idx":0,"uri":42}}""", "uri MUST specify a String value, not a number")]
    [DataRow("""{"status_list":"https://example.com/statuslists/1"}""", "status_list MUST specify a JSON Object")]
    [DataRow("\"revoked\"", "status MUST specify a JSON Object")]
    [DataRow("", "status MUST specify a JSON Object containing at least one reference")]
    public void AStatusClaimThatDoesNotMeetTheClaimRulesIsRefused(string statusObjectJson, string violatedRequirement)
    {
        byte[] statusObject = Encoding.UTF8.GetBytes(statusObjectJson);

        bool isRead = StatusClaimReader.TryRead(statusObject, out StatusClaim? claim);

        Assert.IsFalse(isRead, $"The input violates \"{violatedRequirement}\", so no status claim can be read from it.");
        Assert.IsNull(claim, "A refused read leaves the claim null, never half-populated.");
    }


    /// <summary>
    /// "status: REQUIRED. The status (status) claim MUST specify a JSON Object that contains at least
    /// one reference to a status mechanism."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status List, Section 6.2</see>.
    /// The claim is read where it sits inside the Referenced Token's payload bytes, so the reader is
    /// handed a slice of a larger buffer and must read only that slice: the bytes on either side of
    /// the <c>status</c> object here would each yield a different, wrong answer if the reader
    /// searched past its span.
    /// </summary>
    [TestMethod]
    public void TheClaimIsReadFromASliceOfALargerBuffer()
    {
        const string LeadingBytes = /*lang=json,strict*/ """{"iss":"https://issuer.example","status_list":{"idx":7,"uri":"https://example.com/decoy"},"status":""";
        const string TrailingBytes = /*lang=json,strict*/ ""","status_list":{"idx":9,"uri":"https://example.com/other"}}""";

        byte[] payload = Encoding.UTF8.GetBytes(LeadingBytes + SectionExampleStatusObject + TrailingBytes);
        int statusObjectStart = Encoding.UTF8.GetByteCount(LeadingBytes);
        int statusObjectLength = Encoding.UTF8.GetByteCount(SectionExampleStatusObject);

        bool isRead = StatusClaimReader.TryRead(payload.AsSpan(statusObjectStart, statusObjectLength), out StatusClaim? claim);

        Assert.IsTrue(isRead, "The status claim's own object is well-formed and must be readable in place.");
        Assert.AreEqual(0, claim!.StatusList!.Value.Index, "Only the sliced status object is read; the surrounding bytes carry a different idx.");
        Assert.AreEqual(SectionExampleUri, claim.StatusList!.Value.Uri, "Only the sliced status object is read; the surrounding bytes carry a different uri.");
        Assert.HasCount(1, claim.Mechanisms, "Only the sliced status object's own member is a mechanism the claim names.");
    }
}
