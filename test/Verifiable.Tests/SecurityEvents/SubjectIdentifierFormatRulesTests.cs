using Verifiable.Core.SecurityEvents;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for the member rules of the Subject Identifier Formats that
/// <see cref="SubjectIdentifier.IsValidForKnownFormat"/> checks and for the reserved <c>format</c> member
/// that <see cref="SubjectIdentifier.ToWireObject"/> writes, per
/// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see> and the
/// <c>saml-nameid</c> format of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>.
/// </summary>
/// <remarks>
/// Every identifier is built from literal member names and values so that each row judges the format
/// check and not a factory. No other fixture covers these rules: the Security Event Token tests exercise
/// issuing and reading tokens, not the members a format describes.
/// </remarks>
[TestClass]
internal sealed class SubjectIdentifierFormatRulesTests
{
    /// <summary>
    /// A known format's identifier carries no member its format does not describe.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST NOT contain any members prohibited or not described by its Identifier Format and
    /// MUST contain all members required by its Identifier Format." The Issuer and Subject format describes
    /// <c>iss</c> and <c>sub</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3">Section 3.2.3</see>), the Email
    /// format describes <c>email</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.2">Section 3.2.2</see>), and the SAML
    /// NameID format describes <c>issuer</c>, <c>nameid</c>, <c>nameid_format</c>, <c>name_qualifier</c>,
    /// <c>sp_name_qualifier</c> and <c>sp_provided_id</c>
    /// (<see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>).
    /// </summary>
    /// <param name="caseName">
    /// Which identifier is judged: <c>issSubWithExtra</c>, <c>emailWithPhoneNumber</c>,
    /// <c>samlNameIdWithUnknown</c> or <c>issSub</c>.
    /// </param>
    /// <param name="isExpectedValid">Whether the identifier satisfies its format.</param>
    [TestMethod]
    [DataRow("issSubWithExtra", false, DisplayName = "an iss_sub identifier with an extra member")]
    [DataRow("emailWithPhoneNumber", false, DisplayName = "an email identifier with a phone_number member")]
    [DataRow("samlNameIdWithUnknown", false, DisplayName = "a saml-nameid identifier with an unknown member")]
    [DataRow("issSub", true, DisplayName = "an iss_sub identifier with iss and sub only")]
    public void AKnownFormatCarriesNoMemberItsFormatDoesNotDescribe(string caseName, bool isExpectedValid)
    {
        SubjectIdentifier identifier = caseName switch
        {
            "issSubWithExtra" => new SubjectIdentifier
            {
                Format = "iss_sub",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://issuer.example.com/",
                    ["sub"] = "145234573",
                    ["extra"] = "x"
                }
            },
            "emailWithPhoneNumber" => new SubjectIdentifier
            {
                Format = "email",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["email"] = "user@example.com",
                    ["phone_number"] = "+12065550100"
                }
            },
            "samlNameIdWithUnknown" => new SubjectIdentifier
            {
                Format = "saml-nameid",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["issuer"] = "https://idp.example.com/exk33qwjcwDda7luK346",
                    ["nameid"] = "foo@example.com",
                    ["unknown"] = "x"
                }
            },
            "issSub" => new SubjectIdentifier
            {
                Format = "iss_sub",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://issuer.example.com/",
                    ["sub"] = "145234573"
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        Assert.AreEqual(isExpectedValid, identifier.IsValidForKnownFormat(), caseName);
    }


    /// <summary>
    /// A REQUIRED member of an RFC 9493 format is a non-empty JSON string.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3">RFC 9493 Section 3.2.3</see>: "These
    /// members MUST follow the formats of the "iss" member and "sub" member defined by [RFC7519],
    /// respectively. Both the "iss" member and the "sub" member are REQUIRED and MUST NOT be null or
    /// empty." <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.1">Section 3.2.1</see>: "The
    /// "uri" member is REQUIRED and MUST NOT be null or empty."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.4">Section 3.2.4</see>: "Subject
    /// Identifiers in this format MUST contain an "id" member whose value is a JSON string containing the
    /// opaque string identifier for the subject. The "id" member is REQUIRED and MUST NOT be null or
    /// empty."
    /// </summary>
    /// <param name="caseName">
    /// Which identifier is judged: <c>issSubWithEmptyIss</c>, <c>issSubWithNumericSub</c>,
    /// <c>accountWithEmptyUri</c> or <c>opaque</c>.
    /// </param>
    /// <param name="isExpectedValid">Whether the identifier satisfies its format.</param>
    [TestMethod]
    [DataRow("issSubWithEmptyIss", false, DisplayName = "an iss_sub identifier whose iss is empty")]
    [DataRow("issSubWithNumericSub", false, DisplayName = "an iss_sub identifier whose sub is a number")]
    [DataRow("accountWithEmptyUri", false, DisplayName = "an account identifier whose uri is empty")]
    [DataRow("opaque", true, DisplayName = "an opaque identifier whose id is a non-empty string")]
    public void ARequiredMemberIsANonEmptyString(string caseName, bool isExpectedValid)
    {
        SubjectIdentifier identifier = caseName switch
        {
            "issSubWithEmptyIss" => new SubjectIdentifier
            {
                Format = "iss_sub",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "",
                    ["sub"] = "145234573"
                }
            },
            "issSubWithNumericSub" => new SubjectIdentifier
            {
                Format = "iss_sub",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://issuer.example.com/",
                    ["sub"] = 145234573
                }
            },
            "accountWithEmptyUri" => new SubjectIdentifier
            {
                Format = "account",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["uri"] = ""
                }
            },
            "opaque" => new SubjectIdentifier
            {
                Format = "opaque",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["id"] = "x"
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        Assert.AreEqual(isExpectedValid, identifier.IsValidForKnownFormat(), caseName);
    }


    /// <summary>
    /// An <c>aliases</c> identifier holds one or more Subject Identifiers, none of them itself in the
    /// Aliases Identifier Format.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see>: "Subject
    /// Identifiers in this format MUST contain an "identifiers" member whose value is a JSON array
    /// containing one or more Subject Identifiers." and ""aliases" Subject Identifiers MUST NOT be nested,
    /// i.e., the "identifiers" member of an "aliases" Subject Identifier MUST NOT contain a Subject
    /// Identifier in the Aliases Identifier Format." A string is not a Subject Identifier:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">Section 3</see>, "A Subject Identifier
    /// is a JSON object [RFC8259]" A complex subject is not a Subject Identifier the array holds either:
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.2">OpenID Shared Signals Framework 1.0 Section 3.2</see>
    /// says "A Simple Subject Member has a claim name and a value that is a "Subject Identifier" as defined in the
    /// Subject Identifiers for Security Event Tokens [RFC9493]." and
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.1.4">Section 3.1.4</see>
    /// names the two kinds of value apart: "The value of a Subject Member MAY be a "simple subject" or a
    /// "complex subject"." Refusing an element of the <c>complex</c> format is this library's reading of
    /// RFC 9493 Section 3.2.8's first sentence and of OpenID Shared Signals Framework 1.0 Sections 3.2 and
    /// 3.1.4; no sentence of either specification states it.
    /// </summary>
    /// <param name="caseName">
    /// Which <c>identifiers</c> array is judged: <c>oneEmail</c>, <c>empty</c>, <c>nestedAliases</c>,
    /// <c>stringElement</c> or <c>complexElement</c>.
    /// </param>
    /// <param name="isExpectedValid">Whether the <c>aliases</c> identifier satisfies its format and is well formed.</param>
    [TestMethod]
    [DataRow("oneEmail", true, DisplayName = "one email identifier")]
    [DataRow("empty", false, DisplayName = "an empty identifiers array")]
    [DataRow("nestedAliases", false, DisplayName = "an aliases identifier as an element")]
    [DataRow("stringElement", false, DisplayName = "a string as an element")]
    [DataRow("complexElement", false, DisplayName = "a complex subject as an element")]
    public void AnAliasesIdentifierHoldsOneOrMoreNonNestedIdentifiers(string caseName, bool isExpectedValid)
    {
        List<object> identifiers = caseName switch
        {
            "oneEmail" =>
            [
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "email",
                    ["email"] = "user@example.com"
                }
            ],
            "empty" => [],
            "nestedAliases" =>
            [
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "aliases",
                    ["identifiers"] = new List<object>
                    {
                        new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["format"] = "email",
                            ["email"] = "user@example.com"
                        }
                    }
                }
            ],
            "stringElement" => ["user@example.com"],
            "complexElement" =>
            [
                new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "complex",
                    ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["format"] = "email",
                        ["email"] = "user@example.com"
                    }
                }
            ],
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        SubjectIdentifier aliases = new()
        {
            Format = "aliases",
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["identifiers"] = identifiers
            }
        };

        Assert.AreEqual(isExpectedValid, aliases.IsValidForKnownFormat(), caseName);
        Assert.AreEqual(isExpectedValid, aliases.IsWellFormed(), caseName);
    }


    /// <summary>
    /// The <c>format</c> member is not one of the identifier's own members: an identifier whose members
    /// also hold a <c>format</c> entry does not satisfy its format, and its wire object names the
    /// identifier's own format.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "The
    /// "format" member is reserved for use as described in this specification; Identifier Formats MUST NOT
    /// declare any rules regarding the "format" member." and "A Subject Identifier MUST conform to a
    /// specific Identifier Format and MUST contain a "format" member whose value is the name of that
    /// Identifier Format."
    /// </summary>
    /// <param name="observation">
    /// What is observed of the identifier: <c>isValidForKnownFormat</c> or <c>toWireObjectFormat</c>.
    /// </param>
    /// <param name="expected">The observed value.</param>
    [TestMethod]
    [DataRow("isValidForKnownFormat", false, DisplayName = "the format check refuses the identifier")]
    [DataRow("toWireObjectFormat", "email", DisplayName = "the wire object names the identifier's own format")]
    public void TheFormatMemberIsNotAMemberOfTheIdentifier(string observation, object expected)
    {
        SubjectIdentifier identifier = new()
        {
            Format = "email",
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["email"] = "user@example.com",
                ["format"] = "iss_sub"
            }
        };

        object observed = observation switch
        {
            "isValidForKnownFormat" => identifier.IsValidForKnownFormat(),
            "toWireObjectFormat" => identifier.ToWireObject()["format"],
            _ => throw new ArgumentOutOfRangeException(nameof(observation), observation, null)
        };

        Assert.AreEqual(expected, observed, observation);
    }


    /// <summary>
    /// A <c>saml-nameid</c> identifier carries its REQUIRED members and each OPTIONAL member as a JSON
    /// string.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.2.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.2.1</see>:
    /// "A Subject Identifier in this format MUST contain:" <c>format</c>, <c>issuer</c> and <c>nameid</c>,
    /// and "A Subject Identifier in this format MAY contain:" <c>nameid_format</c>, <c>name_qualifier</c>,
    /// <c>sp_name_qualifier</c> and <c>sp_provided_id</c>, each of them "A JSON string containing the value
    /// of the" corresponding attribute; "nameid: A JSON string containing the SAML Assertion Subject
    /// &lt;NameID&gt; value as defined in [OASIS.saml-core-2.0-os]."
    /// </summary>
    /// <param name="caseName">
    /// Which identifier is judged: <c>required</c>, <c>allOptional</c>, <c>missingNameId</c> or
    /// <c>numericNameIdFormat</c>.
    /// </param>
    /// <param name="isExpectedValid">Whether the identifier satisfies the <c>saml-nameid</c> format.</param>
    [TestMethod]
    [DataRow("required", true, DisplayName = "issuer and nameid")]
    [DataRow("allOptional", true, DisplayName = "issuer, nameid and the four optional members")]
    [DataRow("missingNameId", false, DisplayName = "issuer without nameid")]
    [DataRow("numericNameIdFormat", false, DisplayName = "issuer, nameid and a numeric nameid_format")]
    public void ASamlNameIdIdentifierCarriesItsRequiredAndOptionalMembers(string caseName, bool isExpectedValid)
    {
        Dictionary<string, object> members = caseName switch
        {
            "required" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["issuer"] = "https://idp.example.com/exk33qwjcwDda7luK346",
                ["nameid"] = "foo@example.com"
            },
            "allOptional" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["issuer"] = "https://idp.example.com/exk33qwjcwDda7luK346",
                ["nameid"] = "foo@example.com",
                ["nameid_format"] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                ["name_qualifier"] = "https://idp.example.com/exk33qwjcwDda7luK346",
                ["sp_name_qualifier"] = "https://resource.example.com/saml/sp",
                ["sp_provided_id"] = "sp-provided-7"
            },
            "missingNameId" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["issuer"] = "https://idp.example.com/exk33qwjcwDda7luK346"
            },
            "numericNameIdFormat" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["issuer"] = "https://idp.example.com/exk33qwjcwDda7luK346",
                ["nameid"] = "foo@example.com",
                ["nameid_format"] = 1
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        SubjectIdentifier identifier = new()
        {
            Format = "saml-nameid",
            Members = members
        };

        Assert.AreEqual(isExpectedValid, identifier.IsValidForKnownFormat(), caseName);
    }


    /// <summary>
    /// A format name is known exactly when this library's catalog of Subject Identifier Formats holds it;
    /// any other name, a Collision-Resistant Name or a registered name the catalog does not hold, is not.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "Every
    /// Identifier Format MUST have a unique name registered in the IANA "Security Event Identifier Formats"
    /// registry established in Section 8.1 or a Collision-Resistant Name as defined in [RFC7519]." The
    /// thirteen names are the catalog: the eight formats of RFC 9493, the four of the Shared Signals
    /// Framework and <c>saml-nameid</c>.
    /// </summary>
    /// <param name="format">The format name asked about.</param>
    /// <param name="isExpectedKnown">Whether the catalog holds the name.</param>
    [TestMethod]
    [DataRow("account", true, DisplayName = "account")]
    [DataRow("email", true, DisplayName = "email")]
    [DataRow("iss_sub", true, DisplayName = "iss_sub")]
    [DataRow("opaque", true, DisplayName = "opaque")]
    [DataRow("phone_number", true, DisplayName = "phone_number")]
    [DataRow("did", true, DisplayName = "did")]
    [DataRow("uri", true, DisplayName = "uri")]
    [DataRow("aliases", true, DisplayName = "aliases")]
    [DataRow("jwt_id", true, DisplayName = "jwt_id")]
    [DataRow("saml_assertion_id", true, DisplayName = "saml_assertion_id")]
    [DataRow("ip-addresses", true, DisplayName = "ip-addresses")]
    [DataRow("complex", true, DisplayName = "complex")]
    [DataRow("saml-nameid", true, DisplayName = "saml-nameid")]
    [DataRow("urn:example:subject-format", false, DisplayName = "a Collision-Resistant Name outside the catalog")]
    [DataRow("saml-nameid2", false, DisplayName = "a catalog name with a trailing character")]
    public void ACatalogFormatNameIsKnownAndAnyOtherNameIsNot(string format, bool isExpectedKnown)
    {
        Assert.AreEqual(isExpectedKnown, SubjectIdentifierFormats.IsKnown(format), format);
    }


    /// <summary>
    /// A <c>jwt_id</c> identifier carries exactly <c>iss</c> and <c>jti</c>, and a <c>saml_assertion_id</c>
    /// identifier exactly <c>issuer</c> and <c>assertion_id</c>, each a non-empty JSON string.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.1">OpenID Shared Signals Framework 1.0 Section 3.5.1</see>:
    /// "Subject Identifiers of this type MUST contain the following members:" <c>iss</c> and <c>jti</c>, each
    /// "REQUIRED".
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.2">Section 3.5.2</see>:
    /// "Subject Identifiers of this format MUST contain the following members:" <c>issuer</c> and
    /// <c>assertion_id</c>, each "REQUIRED".
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST NOT contain any members prohibited or not described by its Identifier Format and MUST
    /// contain all members required by its Identifier Format."
    /// </summary>
    /// <param name="caseName">
    /// Which identifier is judged: <c>jwtId</c>, <c>jwtIdWithExtra</c>, <c>jwtIdWithoutJti</c>,
    /// <c>samlAssertionId</c>, <c>samlAssertionIdWithExtra</c> or <c>samlAssertionIdWithNumericAssertionId</c>.
    /// </param>
    /// <param name="isExpectedValid">Whether the identifier satisfies its format.</param>
    [TestMethod]
    [DataRow("jwtId", true, DisplayName = "a jwt_id identifier with iss and jti")]
    [DataRow("jwtIdWithExtra", false, DisplayName = "a jwt_id identifier with an extra member")]
    [DataRow("jwtIdWithoutJti", false, DisplayName = "a jwt_id identifier with iss only")]
    [DataRow("samlAssertionId", true, DisplayName = "a saml_assertion_id identifier with issuer and assertion_id")]
    [DataRow("samlAssertionIdWithExtra", false, DisplayName = "a saml_assertion_id identifier with an extra member")]
    [DataRow("samlAssertionIdWithNumericAssertionId", false, DisplayName = "a saml_assertion_id identifier whose assertion_id is a number")]
    public void AJwtIdOrSamlAssertionIdIdentifierCarriesExactlyItsTwoMembers(string caseName, bool isExpectedValid)
    {
        SubjectIdentifier identifier = caseName switch
        {
            "jwtId" => new SubjectIdentifier
            {
                Format = "jwt_id",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://idp.example.com/123456789/",
                    ["jti"] = "B70BA622-9515-4353-A866-823539EECBC8"
                }
            },
            "jwtIdWithExtra" => new SubjectIdentifier
            {
                Format = "jwt_id",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://idp.example.com/123456789/",
                    ["jti"] = "B70BA622-9515-4353-A866-823539EECBC8",
                    ["extra"] = "x"
                }
            },
            "jwtIdWithoutJti" => new SubjectIdentifier
            {
                Format = "jwt_id",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://idp.example.com/123456789/"
                }
            },
            "samlAssertionId" => new SubjectIdentifier
            {
                Format = "saml_assertion_id",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["issuer"] = "https://idp.example.com/123456789/",
                    ["assertion_id"] = "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"
                }
            },
            "samlAssertionIdWithExtra" => new SubjectIdentifier
            {
                Format = "saml_assertion_id",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["issuer"] = "https://idp.example.com/123456789/",
                    ["assertion_id"] = "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6",
                    ["extra"] = "x"
                }
            },
            "samlAssertionIdWithNumericAssertionId" => new SubjectIdentifier
            {
                Format = "saml_assertion_id",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["issuer"] = "https://idp.example.com/123456789/",
                    ["assertion_id"] = 8
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        Assert.AreEqual(isExpectedValid, identifier.IsValidForKnownFormat(), caseName);
    }


    /// <summary>
    /// An <c>ip-addresses</c> identifier carries exactly its <c>ip-addresses</c> member, a JSON array of one
    /// or more strings, each non-empty.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.5.3">OpenID Shared Signals Framework 1.0 Section 3.5.3</see>:
    /// "Subject Identifiers of this format MUST contain the following members:" <c>ip-addresses</c>,
    /// "REQUIRED. The array of IP addresses of the subject as observed by the Transmitter. The value MUST be
    /// in the format of an array of strings, each one of which represents the [RFC4001] string representation
    /// of an IP address."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST NOT contain any members prohibited or not described by its Identifier Format"
    /// </summary>
    /// <param name="caseName">
    /// Which identifier is judged: <c>twoAddresses</c>, <c>stringValue</c>, <c>emptyArray</c>,
    /// <c>numberElement</c>, <c>emptyStringElement</c> or <c>withExtra</c>.
    /// </param>
    /// <param name="isExpectedValid">Whether the identifier satisfies the <c>ip-addresses</c> format.</param>
    [TestMethod]
    [DataRow("twoAddresses", true, DisplayName = "an array of two address strings")]
    [DataRow("stringValue", false, DisplayName = "a string in the place of the array")]
    [DataRow("emptyArray", false, DisplayName = "an empty array")]
    [DataRow("numberElement", false, DisplayName = "an array holding a number")]
    [DataRow("emptyStringElement", false, DisplayName = "an array holding an empty string")]
    [DataRow("withExtra", false, DisplayName = "the array with an extra member beside it")]
    public void AnIpAddressesIdentifierCarriesAnArrayOfStrings(string caseName, bool isExpectedValid)
    {
        Dictionary<string, object> members = caseName switch
        {
            "twoAddresses" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["ip-addresses"] = new List<object> { "10.29.37.75", "2001:db8::1" }
            },
            "stringValue" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["ip-addresses"] = "10.0.0.1"
            },
            "emptyArray" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["ip-addresses"] = new List<object>()
            },
            "numberElement" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["ip-addresses"] = new List<object> { 5 }
            },
            "emptyStringElement" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["ip-addresses"] = new List<object> { "" }
            },
            "withExtra" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["ip-addresses"] = new List<object> { "10.29.37.75", "2001:db8::1" },
                ["extra"] = "x"
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        SubjectIdentifier identifier = new()
        {
            Format = "ip-addresses",
            Members = members
        };

        Assert.AreEqual(isExpectedValid, identifier.IsValidForKnownFormat(), caseName);
    }


    /// <summary>
    /// A <c>complex</c> identifier holds one or more members, each a Subject Identifier that is a simple
    /// subject: a member of a format the catalog knows satisfies that format, a member of a format the
    /// catalog does not know is admitted, and a member that is itself a <c>complex</c> subject is not.
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.3">OpenID Shared Signals Framework 1.0 Section 3.3</see>:
    /// "A Complex Subject Member has a name and a value that is a JSON [RFC7159] object that has a format
    /// field, and one or more Simple Subject Members."
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.2">Section 3.2</see>:
    /// "A Simple Subject Member has a claim name and a value that is a "Subject Identifier" as defined in the
    /// Subject Identifiers for Security Event Tokens [RFC9493]."
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.1.4">Section 3.1.4</see>:
    /// "The value of a Subject Member MAY be a "simple subject" or a "complex subject"."
    /// <see href="https://openid.net/specs/openid-sharedsignals-framework-1_0.html#section-3.4">Section 3.4</see>
    /// admits "A proprietary subject identifier format that is agreed to between parties."
    /// A member of the <c>aliases</c> format is a Subject Identifier and is admitted when it holds simple
    /// subjects;
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see> makes its
    /// elements Subject Identifiers ("a JSON array containing one or more Subject Identifiers"), so an
    /// <c>aliases</c> member that holds a complex subject is refused. That refusal is this library's reading;
    /// no sentence of either specification states it.
    /// </summary>
    /// <param name="caseName">
    /// Which <c>user</c> member is judged: <c>emailMember</c>, <c>unknownFormatMember</c>, <c>noMember</c>,
    /// <c>stringMember</c>, <c>emailMemberWithoutEmail</c>, <c>complexMember</c>, <c>aliasesMember</c> or
    /// <c>aliasesMemberHoldingAComplexSubject</c>.
    /// </param>
    /// <param name="isExpectedValid">Whether the <c>complex</c> identifier satisfies its format.</param>
    [TestMethod]
    [DataRow("emailMember", true, DisplayName = "a user member of the email format")]
    [DataRow("unknownFormatMember", true, DisplayName = "a user member of a format outside the catalog")]
    [DataRow("noMember", false, DisplayName = "no member")]
    [DataRow("stringMember", false, DisplayName = "a user member that is a string")]
    [DataRow("emailMemberWithoutEmail", false, DisplayName = "a user member of the email format without email")]
    [DataRow("complexMember", false, DisplayName = "a user member that is itself a complex subject")]
    [DataRow("aliasesMember", true, DisplayName = "a user member that is an aliases identifier of two simple identifiers")]
    [DataRow("aliasesMemberHoldingAComplexSubject", false, DisplayName = "a user member that is an aliases identifier holding a complex subject")]
    public void AComplexSubjectHoldsSubjectIdentifiersOfAnyFormatTheCatalogAdmits(string caseName, bool isExpectedValid)
    {
        Dictionary<string, object> members = caseName switch
        {
            "emailMember" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "email",
                    ["email"] = "bar@example.com"
                }
            },
            "unknownFormatMember" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "urn:example:subject-format",
                    ["id"] = "x"
                }
            },
            "noMember" => new Dictionary<string, object>(StringComparer.Ordinal),
            "stringMember" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["user"] = "a-string"
            },
            "emailMemberWithoutEmail" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "email"
                }
            },
            "complexMember" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "complex",
                    ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["format"] = "email",
                        ["email"] = "bar@example.com"
                    }
                }
            },
            "aliasesMember" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "aliases",
                    ["identifiers"] = new List<object>
                    {
                        new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["format"] = "email",
                            ["email"] = "bar@example.com"
                        },
                        new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["format"] = "iss_sub",
                            ["iss"] = "https://example.com/idp1",
                            ["sub"] = "1234"
                        }
                    }
                }
            },
            "aliasesMemberHoldingAComplexSubject" => new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["format"] = "aliases",
                    ["identifiers"] = new List<object>
                    {
                        new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["format"] = "complex",
                            ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                            {
                                ["format"] = "email",
                                ["email"] = "bar@example.com"
                            }
                        }
                    }
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        SubjectIdentifier identifier = new()
        {
            Format = "complex",
            Members = members
        };

        Assert.AreEqual(isExpectedValid, identifier.IsValidForKnownFormat(), caseName);
    }


    /// <summary>
    /// An <c>aliases</c> identifier that repeats an identifier exactly satisfies its format: the sentence on
    /// duplicates binds the party that writes the identifier, and the format check admits them.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 Section 3.2.8</see>: "It MAY
    /// contain multiple instances of the same Identifier Format (e.g., multiple Email Subject Identifiers) but
    /// SHOULD NOT contain exact duplicates."
    /// </summary>
    [TestMethod]
    public void AnAliasesIdentifierMayRepeatAnIdentifier()
    {
        SubjectIdentifier aliases = new()
        {
            Format = "aliases",
            Members = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["identifiers"] = new List<object>
                {
                    new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["format"] = "email",
                        ["email"] = "user@example.com"
                    },
                    new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["format"] = "email",
                        ["email"] = "user@example.com"
                    }
                }
            }
        };

        Assert.IsTrue(aliases.IsValidForKnownFormat());
    }


    /// <summary>
    /// A well-formed identifier names a format and keeps the member rules of a format the catalog knows; an
    /// identifier of a format the catalog does not know is well formed.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value
    /// is the name of that Identifier Format." and "Every Identifier Format MUST have a unique name registered
    /// in the IANA "Security Event Identifier Formats" registry established in Section 8.1 or a
    /// Collision-Resistant Name as defined in [RFC7519]."
    /// </summary>
    /// <param name="caseName">
    /// Which identifier is judged: <c>emptyFormat</c>, <c>whiteSpaceFormat</c>, <c>issSub</c>,
    /// <c>issSubWithExtra</c> or <c>unknownFormat</c>.
    /// </param>
    /// <param name="isExpectedWellFormed">Whether the identifier is well formed.</param>
    [TestMethod]
    [DataRow("emptyFormat", false, DisplayName = "an empty format")]
    [DataRow("whiteSpaceFormat", false, DisplayName = "a format of white space")]
    [DataRow("issSub", true, DisplayName = "an iss_sub identifier with iss and sub")]
    [DataRow("issSubWithExtra", false, DisplayName = "an iss_sub identifier with an extra member")]
    [DataRow("unknownFormat", true, DisplayName = "an identifier of a format outside the catalog")]
    public void AWellFormedIdentifierNamesAFormatAndKeepsItsRules(string caseName, bool isExpectedWellFormed)
    {
        SubjectIdentifier identifier = caseName switch
        {
            "emptyFormat" => new SubjectIdentifier
            {
                Format = "",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["id"] = "x"
                }
            },
            "whiteSpaceFormat" => new SubjectIdentifier
            {
                Format = " ",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["id"] = "x"
                }
            },
            "issSub" => new SubjectIdentifier
            {
                Format = "iss_sub",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://issuer.example.com/",
                    ["sub"] = "145234573"
                }
            },
            "issSubWithExtra" => new SubjectIdentifier
            {
                Format = "iss_sub",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["iss"] = "https://issuer.example.com/",
                    ["sub"] = "145234573",
                    ["extra"] = "x"
                }
            },
            "unknownFormat" => new SubjectIdentifier
            {
                Format = "urn:example:subject-format",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["id"] = "x"
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        Assert.AreEqual(isExpectedWellFormed, identifier.IsWellFormed(), caseName);
    }


    /// <summary>
    /// A <c>format</c> member of white space names no format at any depth: an <c>aliases</c> identifier whose
    /// element carries one, a <c>complex</c> subject whose member carries one, and an identifier whose own
    /// format is one are none of them Subject Identifiers.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value
    /// is the name of that Identifier Format."
    /// </summary>
    /// <param name="caseName">
    /// Which identifier is judged: <c>aliasesElement</c>, <c>complexMember</c> or <c>tabFormat</c>.
    /// </param>
    [TestMethod]
    [DataRow("aliasesElement", DisplayName = "an aliases identifier whose one element has a format of white space")]
    [DataRow("complexMember", DisplayName = "a complex subject whose one member has a format of white space")]
    [DataRow("tabFormat", DisplayName = "an identifier whose own format is a tab")]
    public void AMemberOfABlankFormatIsNoSubjectIdentifier(string caseName)
    {
        SubjectIdentifier identifier = caseName switch
        {
            "aliasesElement" => new SubjectIdentifier
            {
                Format = "aliases",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["identifiers"] = new List<object>
                    {
                        new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["format"] = " ",
                            ["id"] = "x"
                        }
                    }
                }
            },
            "complexMember" => new SubjectIdentifier
            {
                Format = "complex",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["user"] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["format"] = " ",
                        ["id"] = "x"
                    }
                }
            },
            "tabFormat" => new SubjectIdentifier
            {
                Format = "\t",
                Members = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["id"] = "x"
                }
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        Assert.IsFalse(identifier.IsValidForKnownFormat(), caseName);
        Assert.IsFalse(identifier.IsWellFormed(), caseName);
    }
}
