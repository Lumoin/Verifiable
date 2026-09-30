using Verifiable.Core.SecurityEvents;
using Verifiable.OAuth.IdJag;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit tests for <see cref="SamlNameIdSubjectIdentifier.TryParse"/> — the redeem-side parsing of the
/// <c>saml-nameid</c> <c>sub_id</c> claim per draft-ietf-oauth-identity-assertion-authz-grant §3.2.1
/// (the REQUIRED <c>format</c>/<c>issuer</c>/<c>nameid</c> members) and §3.2.2 (a malformed identifier or
/// one of an unsupported Subject Identifier Format is "no usable SAML NameID" and must not parse, so a
/// Resource Authorization Server that requires one rejects the grant), and for the projection of
/// <see cref="SamlNameIdSubjectIdentifier.ToSubjectIdentifier"/> and
/// <see cref="SamlNameIdSubjectIdentifier.TryFrom"/> to and from an RFC 9493 Subject Identifier.
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
        _ = claim.Remove(SamlNameIdMemberNames.NameId);

        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse(claim, out SamlNameIdSubjectIdentifier? identifier));
        Assert.IsNull(identifier);
    }


    /// <summary>§3.2.1: a value missing the REQUIRED <c>issuer</c> is malformed — it does not parse (§3.2.2).</summary>
    [TestMethod]
    public void RejectsMissingIssuer()
    {
        Dictionary<string, object> claim = WellFormedRequiredOnly();
        _ = claim.Remove(SamlNameIdMemberNames.Issuer);

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


    /// <summary>
    /// A <c>saml-nameid</c> claim that breaks the member rules of its format does not parse: a member the
    /// format does not describe, an optional member that is not a JSON string, and an optional member that is
    /// a JSON null are each refused, and the parsed identifier is <see langword="null"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "Every member
    /// within a Subject Identifier MUST match the rules specified for that member by this specification or by a
    /// Subject Identifier's Identifier Format. A Subject Identifier MUST NOT contain any members prohibited or
    /// not described by its Identifier Format and MUST contain all members required by its Identifier Format."
    /// The check covers the members present, their JSON types, the members a format does not describe and the
    /// reserved <c>format</c> member; the rules on a member's value are the caller's, which
    /// <see cref="SubjectIdentifier.IsValidForKnownFormat"/> names.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>:
    /// "nameid_format: A JSON string containing the value of the Format attribute on the SAML Assertion Subject
    /// &lt;NameID&gt; as defined in [OASIS.saml-core-2.0-os]." and "sp_name_qualifier: A JSON string containing
    /// the value of the SPNameQualifier attribute on the SAML Assertion Subject &lt;NameID&gt; as defined in
    /// [OASIS.saml-core-2.0-os]."
    /// </summary>
    /// <param name="caseName">
    /// The breach: <c>anUndescribedMember</c>, <c>aNumericNameIdFormat</c> or <c>aNullSpNameQualifier</c>.
    /// </param>
    [TestMethod]
    [DataRow("anUndescribedMember", DisplayName = "a member the format does not describe")]
    [DataRow("aNumericNameIdFormat", DisplayName = "a nameid_format that is a number")]
    [DataRow("aNullSpNameQualifier", DisplayName = "an sp_name_qualifier that is a JSON null")]
    public void TryParseRefusesAnIdentifierThatBreaksItsFormat(string caseName)
    {
        (string Name, object Value) breach = caseName switch
        {
            "anUndescribedMember" => ("extra", "x"),
            "aNumericNameIdFormat" => (SamlNameIdMemberNames.NameIdFormat, 5L),
            "aNullSpNameQualifier" => (SamlNameIdMemberNames.SpNameQualifier, null!),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        Dictionary<string, object> claim = WellFormedRequiredOnly();
        claim[breach.Name] = breach.Value;

        bool isParsed = SamlNameIdSubjectIdentifier.TryParse(claim, out SamlNameIdSubjectIdentifier? identifier);

        Assert.IsFalse(isParsed, caseName);
        Assert.IsNull(identifier, caseName);
    }


    /// <summary>§3.2.2: a value that is not a JSON object (or absent) is not a usable SAML NameID identifier.</summary>
    [TestMethod]
    public void RejectsNonObjectOrAbsentValue()
    {
        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse("not-an-object", out _));
        Assert.IsFalse(SamlNameIdSubjectIdentifier.TryParse(null, out _));
    }


    /// <summary>
    /// A SAML NameID identifier projects to an RFC 9493 Subject Identifier of the <c>saml-nameid</c> format
    /// carrying the REQUIRED members and exactly the optional members that are present, and reads back to
    /// an equal identifier.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value
    /// is the name of that Identifier Format."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>:
    /// "The SAML NameID Subject Identifier Format is identified by the name saml-nameid"; "A Subject
    /// Identifier in this format MUST contain:" <c>format</c>, <c>issuer</c> and <c>nameid</c>, and "A Subject
    /// Identifier in this format MAY contain:" <c>nameid_format</c>, <c>name_qualifier</c>,
    /// <c>sp_name_qualifier</c> and <c>sp_provided_id</c>.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.2">Section 3.2.2</see>:
    /// "Each optional field MUST be included exactly when the corresponding attribute is present on that
    /// &lt;NameID&gt; or in the configured mapping."
    /// </summary>
    /// <param name="caseName">
    /// Which identifier is projected: <c>requiredOnly</c> or <c>withNameIdFormatAndSpNameQualifier</c>.
    /// </param>
    [TestMethod]
    [DataRow("requiredOnly", DisplayName = "the REQUIRED members only")]
    [DataRow("withNameIdFormatAndSpNameQualifier", DisplayName = "with nameid_format and sp_name_qualifier")]
    public void ProjectsToAnRfc9493SubjectIdentifier(string caseName)
    {
        SamlNameIdSubjectIdentifier samlIdentifier = caseName switch
        {
            "requiredOnly" => new SamlNameIdSubjectIdentifier
            {
                Issuer = "https://idp.example.com/saml",
                NameId = "alice@example.com"
            },
            "withNameIdFormatAndSpNameQualifier" => new SamlNameIdSubjectIdentifier
            {
                Issuer = "https://idp.example.com/saml",
                NameId = "alice@example.com",
                NameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                SpNameQualifier = "https://resource.example.com/saml/sp"
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        Dictionary<string, object> expectedMembers = caseName switch
        {
            "requiredOnly" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["issuer"] = "https://idp.example.com/saml",
                ["nameid"] = "alice@example.com"
            },
            "withNameIdFormatAndSpNameQualifier" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["issuer"] = "https://idp.example.com/saml",
                ["nameid"] = "alice@example.com",
                ["nameid_format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                ["sp_name_qualifier"] = "https://resource.example.com/saml/sp"
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        SubjectIdentifier projected = samlIdentifier.ToSubjectIdentifier();

        Assert.AreEqual("saml-nameid", projected.Format, caseName);
        Assert.HasCount(expectedMembers.Count, projected.Members, caseName);
        foreach(KeyValuePair<string, object> expected in expectedMembers)
        {
            Assert.IsTrue(projected.Members.TryGetValue(expected.Key, out object? actual), expected.Key);
            Assert.AreEqual(expected.Value, actual, expected.Key);
        }

        Assert.IsTrue(projected.IsValidForKnownFormat(), caseName);
        Assert.IsTrue(SamlNameIdSubjectIdentifier.TryFrom(projected, out SamlNameIdSubjectIdentifier? readBack), caseName);
        Assert.AreEqual(samlIdentifier, readBack, caseName);
    }


    /// <summary>
    /// The text of a <see cref="SamlNameIdSubjectIdentifier"/> names its SAML issuer and which optional members
    /// are present, and neither the NameID nor the value of any optional member: the NameID and its qualifiers
    /// can identify a person, so they stay out of every text a log or a trace receives. The rule is this
    /// library's; no clause of a specification states it.
    /// </summary>
    /// <param name="caseName">Which identifier is rendered: <c>requiredOnly</c> or <c>everyMember</c>.</param>
    [TestMethod]
    [DataRow("requiredOnly", DisplayName = "the REQUIRED members only")]
    [DataRow("everyMember", DisplayName = "with every optional member")]
    public void TheIdentifierRendersItsIssuerAndNoNameId(string caseName)
    {
        SamlNameIdSubjectIdentifier samlIdentifier = caseName switch
        {
            "requiredOnly" => new SamlNameIdSubjectIdentifier
            {
                Issuer = SamlIssuer,
                NameId = SamlNameIdValue
            },
            "everyMember" => new SamlNameIdSubjectIdentifier
            {
                Issuer = SamlIssuer,
                NameId = SamlNameIdValue,
                NameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                NameQualifier = "https://idp.example.com/qualifier",
                SpNameQualifier = "https://resource.example.com/saml/sp",
                SpProvidedId = "sp-provided-9"
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        string text = samlIdentifier.ToString();

        Assert.DoesNotContain(SamlNameIdValue, text);
        foreach(string? optionalValue in new[] { samlIdentifier.NameIdFormat, samlIdentifier.NameQualifier, samlIdentifier.SpNameQualifier, samlIdentifier.SpProvidedId })
        {
            if(optionalValue is not null)
            {
                Assert.DoesNotContain(optionalValue, text);
            }
        }

        Assert.Contains(SamlIssuer, text);
        string presence = caseName == "everyMember" ? "True" : "False";
        Assert.Contains($"HasNameIdFormat={presence}", text);
        Assert.Contains($"HasNameQualifier={presence}", text);
        Assert.Contains($"HasSpNameQualifier={presence}", text);
        Assert.Contains($"HasSpProvidedId={presence}", text);
    }
}
