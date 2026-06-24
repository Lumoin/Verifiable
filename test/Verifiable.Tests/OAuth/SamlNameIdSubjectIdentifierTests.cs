using Verifiable.OAuth.IdJag;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit tests for <see cref="SamlNameIdSubjectIdentifier.TryParse"/> — the redeem-side parsing of the
/// <c>saml-nameid</c> <c>sub_id</c> claim per draft-ietf-oauth-identity-assertion-authz-grant §3.2.1
/// (the REQUIRED <c>format</c>/<c>issuer</c>/<c>nameid</c> members) and §3.2.2 (a malformed identifier or
/// one of an unsupported Subject Identifier Format is "no usable SAML NameID" and must not parse, so a
/// Resource Authorization Server that requires one rejects the grant).
/// </summary>
[TestClass]
internal sealed class SamlNameIdSubjectIdentifierTests
{
    private const string SamlIssuer = "https://idp.example.com/saml";
    private const string SamlNameIdValue = "alice@example.com";


    /// <summary>Builds a well-formed <c>saml-nameid</c> claim object carrying only the REQUIRED members.</summary>
    private static Dictionary<string, object> WellFormedRequiredOnly() =>
        new(StringComparer.Ordinal)
        {
            [SamlNameIdMemberNames.Format] = SamlNameIdMemberNames.SamlNameIdFormat,
            [SamlNameIdMemberNames.Issuer] = SamlIssuer,
            [SamlNameIdMemberNames.NameId] = SamlNameIdValue
        };


    /// <summary>§3.2.1: a value with the REQUIRED members parses; absent optional members surface as null.</summary>
    [TestMethod]
    public void ParsesRequiredMembersAndLeavesAbsentOptionalsNull()
    {
        bool parsed = SamlNameIdSubjectIdentifier.TryParse(WellFormedRequiredOnly(), out SamlNameIdSubjectIdentifier? identifier);

        Assert.IsTrue(parsed);
        Assert.AreEqual(SamlIssuer, identifier!.Issuer);
        Assert.AreEqual(SamlNameIdValue, identifier.NameId);
        Assert.IsNull(identifier.NameIdFormat);
        Assert.IsNull(identifier.NameQualifier);
        Assert.IsNull(identifier.SpNameQualifier);
        Assert.IsNull(identifier.SpProvidedId);
    }


    /// <summary>§3.2.1 / §3.2.2: each optional member is surfaced exactly when present; the rest stay null.</summary>
    [TestMethod]
    public void ParsesOptionalMembersExactlyWhenPresent()
    {
        Dictionary<string, object> claim = WellFormedRequiredOnly();
        claim[SamlNameIdMemberNames.NameIdFormat] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
        claim[SamlNameIdMemberNames.SpNameQualifier] = "https://resource.example.com/saml/sp";

        bool parsed = SamlNameIdSubjectIdentifier.TryParse(claim, out SamlNameIdSubjectIdentifier? identifier);

        Assert.IsTrue(parsed);
        Assert.AreEqual("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", identifier!.NameIdFormat);
        Assert.AreEqual("https://resource.example.com/saml/sp", identifier.SpNameQualifier);
        Assert.IsNull(identifier.NameQualifier, "an absent optional member stays null.");
        Assert.IsNull(identifier.SpProvidedId, "an absent optional member stays null.");
    }


    /// <summary>§3.2.1: a value missing the REQUIRED <c>nameid</c> is malformed — it does not parse (§3.2.2).</summary>
    [TestMethod]
    public void RejectsMissingNameId()
    {
        Dictionary<string, object> claim = WellFormedRequiredOnly();
        claim.Remove(SamlNameIdMemberNames.NameId);

        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse(claim, out SamlNameIdSubjectIdentifier? identifier));
        Assert.IsNull(identifier);
    }


    /// <summary>§3.2.1: a value missing the REQUIRED <c>issuer</c> is malformed — it does not parse (§3.2.2).</summary>
    [TestMethod]
    public void RejectsMissingIssuer()
    {
        Dictionary<string, object> claim = WellFormedRequiredOnly();
        claim.Remove(SamlNameIdMemberNames.Issuer);

        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse(claim, out _));
    }


    /// <summary>§3.2.1: an empty REQUIRED member is malformed — it does not parse.</summary>
    [TestMethod]
    public void RejectsEmptyNameId()
    {
        Dictionary<string, object> claim = WellFormedRequiredOnly();
        claim[SamlNameIdMemberNames.NameId] = string.Empty;

        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse(claim, out _));
    }


    /// <summary>§3.2.2: a different Subject Identifier Format is unsupported — it does not parse as saml-nameid.</summary>
    [TestMethod]
    public void RejectsUnsupportedFormat()
    {
        Dictionary<string, object> claim = WellFormedRequiredOnly();
        claim[SamlNameIdMemberNames.Format] = "account";

        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse(claim, out _));
    }


    /// <summary>§3.2.2: a value that is not a JSON object (or absent) is not a usable SAML NameID identifier.</summary>
    [TestMethod]
    public void RejectsNonObjectOrAbsentValue()
    {
        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse("not-an-object", out _));
        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse(null, out _));
    }
}
