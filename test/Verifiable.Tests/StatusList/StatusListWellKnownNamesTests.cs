using System.Text;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.StatusList;
using Verifiable.JCose;
using Verifiable.Json.StatusList;
using Verifiable.OAuth;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for the well-known names the Status List Token is spelled with: the JWT type
/// <c>statuslist+jwt</c>, the JWT claim names <c>status</c>, <c>status_list</c> and <c>ttl</c> the
/// specification registers with IANA, and the Section 4.2 / Section 6.2 object member names
/// <c>bits</c>, <c>lst</c>, <c>aggregation_uri</c>, <c>idx</c> and <c>uri</c>. Each name is compared
/// against the literal the specification prints, and each tier that spells the same name is proved to
/// read it from the one place it is defined rather than carrying a second copy of the literal.
/// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
/// </summary>
[TestClass]
internal sealed class StatusListWellKnownNamesTests
{
    /// <summary>Gets or sets the context for the current test run.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// "The following content applies to the JWT Header: typ: REQUIRED. The JWT type MUST be
    /// statuslist+jwt." The type is that literal, and its UTF-8 source form spells the same characters.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TheStatusListJwtTypeIsTheValueTheHeaderMustCarry()
    {
        Assert.AreEqual("statuslist+jwt", WellKnownMediaTypes.Jwt.StatusListJwt, "The JWT type MUST be statuslist+jwt.");
        Assert.AreEqual("statuslist+jwt", Encoding.UTF8.GetString(WellKnownMediaTypes.Jwt.StatusListJwtUtf8), "The UTF-8 source literal must spell the same type.");
    }


    /// <summary>
    /// "The typ (type) Header Parameter defined by [JWS] and [JWE] is used by JWT applications to
    /// declare the media type [IANA.MediaTypes] of this complete JWT" — and media type names are not
    /// case sensitive, so a header carrying the type in any casing declares the same Status List Token
    /// and must be recognized as such, canonicalizing onto the one instance the table holds.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-5.1">RFC 7519, Section 5.1</see>.
    /// </summary>
    /// <param name="typ">The type value as a header might carry it.</param>
    [TestMethod]
    [DataRow("statuslist+jwt")]
    [DataRow("STATUSLIST+JWT")]
    [DataRow("StatusList+Jwt")]
    [DataRow("statuslist+JWT")]
    public void TheStatusListJwtTypeIsRecognizedRegardlessOfCase(string typ)
    {
        Assert.IsTrue(WellKnownMediaTypes.Jwt.IsStatusListJwt(typ), "A type differing only in case declares the same Status List Token.");
        Assert.IsTrue(WellKnownMediaTypes.Jwt.Equals(typ, WellKnownMediaTypes.Jwt.StatusListJwt), "Type comparison is case-insensitive.");
        Assert.AreSame(WellKnownMediaTypes.Jwt.StatusListJwt, WellKnownMediaTypes.Jwt.GetCanonicalizedValue(typ), "A recognized type canonicalizes onto the one instance the table holds.");
    }


    /// <summary>
    /// The same sentence read the other way: a header carrying any other type does not declare a
    /// Status List Token in JWT format, so none of the neighbouring types may be mistaken for it —
    /// the CWT type of Section 5.2 least of all.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    /// <param name="typ">A type value that is not <c>statuslist+jwt</c>.</param>
    [TestMethod]
    [DataRow("statuslist+cwt")]
    [DataRow("application/statuslist+jwt")]
    [DataRow("statuslist")]
    [DataRow("kb+jwt")]
    [DataRow("JWT")]
    public void ATypeThatIsNotStatusListJwtIsNotRecognizedAsOne(string typ)
    {
        Assert.IsFalse(WellKnownMediaTypes.Jwt.IsStatusListJwt(typ), $"'{typ}' does not declare a Status List Token in JWT format.");
    }


    /// <summary>
    /// The <c>typ</c> value has one home: the media-type table the OAuth layer offers beside the HTTP
    /// content types must hand back that very instance, so no second copy of the literal can drift.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TheStatusListMediaTypesNameTheSameStatusListJwtType()
    {
        Assert.AreSame(WellKnownMediaTypes.Jwt.StatusListJwt, StatusListMediaTypes.StatusListJwt, "The two spellings of the JWT type must be one and the same instance.");
        Assert.IsTrue(StatusListMediaTypes.StatusListJwtUtf8.SequenceEqual(WellKnownMediaTypes.Jwt.StatusListJwtUtf8), "The two UTF-8 source literals must be the same bytes.");
    }


    /// <summary>
    /// The three claim names this specification registers in the IANA "JSON Web Token Claims"
    /// registry — "Claim Name: status" / "Claim Name: status_list" / "Claim Name: ttl" — are those
    /// literals, and each UTF-8 source form spells the same characters.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TheStatusListClaimNamesAreTheOnesTheRegistryRecords()
    {
        Assert.AreEqual("status", WellKnownJwtClaimNames.Status, "The registered claim name is 'status'.");
        Assert.AreEqual("status_list", WellKnownJwtClaimNames.StatusList, "The registered claim name is 'status_list'.");
        Assert.AreEqual("ttl", WellKnownJwtClaimNames.TimeToLive, "The registered claim name is 'ttl'.");
        Assert.AreEqual("status", Encoding.UTF8.GetString(WellKnownJwtClaimNames.StatusUtf8), "The UTF-8 source literal must spell the same claim name.");
        Assert.AreEqual("status_list", Encoding.UTF8.GetString(WellKnownJwtClaimNames.StatusListUtf8), "The UTF-8 source literal must spell the same claim name.");
        Assert.AreEqual("ttl", Encoding.UTF8.GetString(WellKnownJwtClaimNames.TimeToLiveUtf8), "The UTF-8 source literal must spell the same claim name.");
    }


    /// <summary>
    /// A claims set arrives with its names as freshly built strings, never as the table's own
    /// instances, so each claim must still be recognized by value and canonicalize onto the one
    /// instance the table holds.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TheStatusListClaimNamesAreRecognizedWhenTheyArriveAsFreshStrings()
    {
        string status = new(WellKnownJwtClaimNames.Status);
        string statusList = new(WellKnownJwtClaimNames.StatusList);
        string timeToLive = new(WellKnownJwtClaimNames.TimeToLive);

        Assert.IsFalse(object.ReferenceEquals(WellKnownJwtClaimNames.Status, status), "The premise is a claim name that is not the table's own instance.");
        Assert.IsTrue(WellKnownJwtClaimNames.IsStatus(status), "'status' must be recognized by value.");
        Assert.IsTrue(WellKnownJwtClaimNames.IsStatusList(statusList), "'status_list' must be recognized by value.");
        Assert.IsTrue(WellKnownJwtClaimNames.IsTimeToLive(timeToLive), "'ttl' must be recognized by value.");
        Assert.AreSame(WellKnownJwtClaimNames.Status, WellKnownJwtClaimNames.GetCanonicalizedValue(status), "'status' must canonicalize onto the one instance the table holds.");
        Assert.AreSame(WellKnownJwtClaimNames.StatusList, WellKnownJwtClaimNames.GetCanonicalizedValue(statusList), "'status_list' must canonicalize onto the one instance the table holds.");
        Assert.AreSame(WellKnownJwtClaimNames.TimeToLive, WellKnownJwtClaimNames.GetCanonicalizedValue(timeToLive), "'ttl' must canonicalize onto the one instance the table holds.");
    }


    /// <summary>
    /// JWT claim names are case-sensitive, unlike the <c>typ</c> media type, so a claims set spelling
    /// a name in another casing carries a different claim entirely and must not be read as this one.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">RFC 7519, Section 4</see>.
    /// </summary>
    /// <param name="claimName">The differently cased claim name.</param>
    [TestMethod]
    [DataRow("Status")]
    [DataRow("STATUS")]
    [DataRow("Status_List")]
    [DataRow("STATUS_LIST")]
    [DataRow("TTL")]
    [DataRow("Ttl")]
    public void TheStatusListClaimNamesAreCaseSensitive(string claimName)
    {
        Assert.IsFalse(WellKnownJwtClaimNames.IsStatus(claimName), $"'{claimName}' is not the claim name 'status'.");
        Assert.IsFalse(WellKnownJwtClaimNames.IsStatusList(claimName), $"'{claimName}' is not the claim name 'status_list'.");
        Assert.IsFalse(WellKnownJwtClaimNames.IsTimeToLive(claimName), $"'{claimName}' is not the claim name 'ttl'.");
    }


    /// <summary>
    /// "The StatusList structure is a JSON Object that contains the following members: bits … lst …
    /// aggregation_uri" and, for the Referenced Token's reference object, "idx" and "uri". The member
    /// names are exactly those literals.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>
    /// and <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Section 6.2</see>.
    /// </summary>
    /// <param name="memberNameInTheSpecification">The member name as the specification prints it.</param>
    /// <param name="memberName">The member name as it is defined for the library to read and write.</param>
    [TestMethod]
    [DataRow("bits", StatusListMemberNames.Bits)]
    [DataRow("lst", StatusListMemberNames.List)]
    [DataRow("aggregation_uri", StatusListMemberNames.AggregationUri)]
    [DataRow("idx", StatusListMemberNames.Index)]
    [DataRow("uri", StatusListMemberNames.Uri)]
    public void TheStatusListObjectMemberNamesAreTheOnesTheStructureDefines(string memberNameInTheSpecification, string memberName)
    {
        Assert.AreEqual(memberNameInTheSpecification, memberName, $"The structure's member is spelled '{memberNameInTheSpecification}'.");
    }


    /// <summary>
    /// The JSON tier and the CBOR tier encode the same members of the same structure, so each must
    /// read the member name from the one place it is defined — a second copy of a literal is a second
    /// place for the two tiers to disagree about what the wire says.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.2">Token Status List, Section 4.2</see>.
    /// </summary>
    /// <param name="memberName">The member name as it is defined for both tiers to read and write.</param>
    /// <param name="jsonTierName">The member name as the JSON tier spells it.</param>
    /// <param name="cborTierName">The member name as the CBOR tier spells it.</param>
    [TestMethod]
    [DataRow(StatusListMemberNames.Bits, StatusListJsonConstants.Bits, StatusListCborConstants.Bits)]
    [DataRow(StatusListMemberNames.List, StatusListJsonConstants.List, StatusListCborConstants.List)]
    [DataRow(StatusListMemberNames.AggregationUri, StatusListJsonConstants.AggregationUri, StatusListCborConstants.AggregationUri)]
    [DataRow(StatusListMemberNames.Index, StatusListJsonConstants.Index, StatusListCborConstants.Index)]
    [DataRow(StatusListMemberNames.Uri, StatusListJsonConstants.Uri, StatusListCborConstants.Uri)]
    public void TheJsonAndCborTiersSpellEveryMemberNameTheSameWay(string memberName, string jsonTierName, string cborTierName)
    {
        Assert.AreEqual(memberName, jsonTierName, $"The JSON tier must spell '{memberName}' as the structure defines it.");
        Assert.AreEqual(memberName, cborTierName, $"The CBOR tier must spell '{memberName}' as the structure defines it.");
    }


    /// <summary>
    /// The same one-home rule for the claim names the JSON tier spells: <c>status</c>,
    /// <c>status_list</c> and <c>ttl</c> are registered JWT claims, so the tier must hand back the very
    /// instances the claim-name table holds.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void TheJsonTierSpellsTheClaimNamesTheRegistryRecords()
    {
        Assert.AreSame(WellKnownJwtClaimNames.Status, StatusListJsonConstants.Status, "'status' must be the one instance the claim-name table holds.");
        Assert.AreSame(WellKnownJwtClaimNames.StatusList, StatusListJsonConstants.StatusList, "'status_list' must be the one instance the claim-name table holds.");
        Assert.AreSame(WellKnownJwtClaimNames.TimeToLive, StatusListJsonConstants.TimeToLive, "'ttl' must be the one instance the claim-name table holds.");
    }
}
