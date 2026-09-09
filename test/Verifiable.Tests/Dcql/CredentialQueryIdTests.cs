using System;
using System.Collections.Generic;
using Verifiable.Core.Dcql;

namespace Verifiable.Tests.Dcql;

/// <summary>
/// Proves <see cref="CredentialQueryId"/> admits exactly the identifier values
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
/// OpenID for Verifiable Presentations 1.0, Section 6.1</see> allows: the constructor refuses an
/// empty value and any character outside <c>[A-Za-z0-9_-]</c>, <see cref="CredentialQueryId.TryCreate"/>
/// answers the same verdict without throwing, equality is ordinal over the value, and
/// <see cref="CredentialQueryId.ToString"/> reports the bare value the wire carries.
/// </summary>
/// <remarks>
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
/// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "id: REQUIRED. A string identifying
/// the Credential in the response and, if provided, the constraints in credential_sets. The value
/// MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters.
/// Within the Authorization Request, the same id MUST NOT be present more than once."
/// </remarks>
[TestClass]
internal sealed class CredentialQueryIdTests
{
    /// <summary>The MSTest-supplied context of the currently executing test.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Identifier values built only from Section 6.1's allowed characters: an upper-case letter, a
    /// lower-case letter, a digit, the underscore, the hyphen, and mixtures of all five.
    /// </summary>
    private static string[] AllowedValues { get; } =
    [
        "A",
        "z",
        "0",
        "9",
        "_",
        "-",
        "pid",
        "PID",
        "identity_credential",
        "authority-constrained",
        "pid_2-x"
    ];

    /// <summary>
    /// Identifier values carrying one character Section 6.1's class does not allow: a space, a full
    /// stop, a colon, a solidus, a NUL, a non-ASCII letter, and a Cyrillic homoglyph (U+0440) that
    /// renders like the allowed Latin <c>p</c> of <c>pid</c> but is a different character.
    /// </summary>
    private static string[] RefusedValues { get; } =
    [
        "pid 2",
        "pid.2",
        "pid:2",
        "pid/2",
        "pid\0",
        "pidö",
        "рid"
    ];


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." An empty value
    /// is not an identifier, so no identifier can be minted over it.
    /// </summary>
    [TestMethod]
    public void CredentialQueryIdOverAnEmptyValueIsRefused()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => new CredentialQueryId(string.Empty),
            "Section 6.1: the value MUST be a non-empty string, so an empty value is refused.");

        Assert.AreEqual(
            "value",
            exception.ParamName,
            "The refusal names the parameter carrying the Section 6.1-invalid value.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." A value of
    /// nothing but spaces is non-empty as a string yet carries no allowed character, so it is
    /// refused on the character class rather than passed on as an identifier of blanks.
    /// </summary>
    [TestMethod]
    public void CredentialQueryIdOverAWhitespaceOnlyValueIsRefused()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => new CredentialQueryId("   "),
            "Section 6.1: a space is outside the alphanumeric, underscore and hyphen class, so a whitespace-only value is refused.");

        Assert.AreEqual(
            "value",
            exception.ParamName,
            "The refusal names the parameter carrying the Section 6.1-invalid value.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." Every character
    /// of that class — letters of either case, digits, the underscore and the hyphen, alone or
    /// mixed — is an identifier the type carries unchanged.
    /// </summary>
    [TestMethod]
    public void CredentialQueryIdOverEveryAllowedCharacterClassIsAccepted()
    {
        foreach(string value in AllowedValues)
        {
            CredentialQueryId identifier = new(value);

            Assert.AreEqual(
                value,
                identifier.Value,
                $"Section 6.1 allows '{value}', so the identifier carries it unchanged.");
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." A value
    /// carrying any other character — punctuation, a path separator, a NUL, a non-ASCII letter, or
    /// a homoglyph that merely renders like an allowed one — is not an identifier.
    /// </summary>
    [TestMethod]
    public void CredentialQueryIdOverACharacterOutsideTheAllowedClassIsRefused()
    {
        foreach(string value in RefusedValues)
        {
            ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
                () => new CredentialQueryId(value),
                $"Section 6.1 does not allow every character of '{value}', so it is refused.");

            Assert.AreEqual(
                "value",
                exception.ParamName,
                $"The refusal of '{value}' names the parameter carrying the Section 6.1-invalid value.");
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters." Input read off
    /// the wire may carry anything, including no <c>id</c> member at all, so the wire boundary reads
    /// the same verdict as an answer rather than as a thrown exception.
    /// </summary>
    [TestMethod]
    public void TryCreateOverARefusedValueAnswersFalse()
    {
        Assert.IsFalse(
            CredentialQueryId.TryCreate(null, out CredentialQueryId? overNull),
            "Section 6.1 requires an id, so an absent value yields no identifier.");
        Assert.IsNull(overNull, "A refused candidate yields no identifier.");

        Assert.IsFalse(
            CredentialQueryId.TryCreate(string.Empty, out CredentialQueryId? overEmpty),
            "Section 6.1: the value MUST be a non-empty string.");
        Assert.IsNull(overEmpty, "A refused candidate yields no identifier.");

        foreach(string value in RefusedValues)
        {
            Assert.IsFalse(
                CredentialQueryId.TryCreate(value, out CredentialQueryId? refused),
                $"Section 6.1 does not allow every character of '{value}', so it yields no identifier.");
            Assert.IsNull(refused, $"The refused candidate '{value}' yields no identifier.");
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "A string identifying the
    /// Credential in the response and, if provided, the constraints in credential_sets." A wire
    /// value satisfying the character class yields the identifier that keys both, carrying the
    /// value unchanged.
    /// </summary>
    [TestMethod]
    public void TryCreateOverAnAllowedValueAnswersTrueAndCarriesTheValue()
    {
        foreach(string value in AllowedValues)
        {
            bool isCreated = CredentialQueryId.TryCreate(value, out CredentialQueryId? identifier);

            Assert.IsTrue(
                isCreated,
                $"Section 6.1 allows '{value}', so it yields an identifier.");
            Assert.IsNotNull(
                identifier,
                $"Section 6.1 allows '{value}', so an identifier is produced.");
            Assert.AreEqual(
                value,
                identifier.Value,
                $"Section 6.1 allows '{value}', so the identifier carries it unchanged.");
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">
    /// OpenID for Verifiable Presentations 1.0, Section 8.1</see>: "vp_token: REQUIRED. This is a
    /// JSON-encoded object containing entries where the key is the id value used for a Credential
    /// Query in the DCQL query and the value is an array of one or more Presentations that match
    /// the respective Credential Query." Two identifiers over the same value therefore address the
    /// same entry: they are equal and hash alike, so either one reaches the same map entry.
    /// </summary>
    [TestMethod]
    public void CredentialQueryIdsOverTheSameValueAreEqualAndHashEqual()
    {
        CredentialQueryId first = new("pid_2-x");
        CredentialQueryId second = new("pid_2-x");

        Assert.AreEqual(
            first,
            second,
            "Section 8.1 keys the response on the id value, so two identifiers over the same value are equal.");
        Assert.AreEqual(
            first.GetHashCode(),
            second.GetHashCode(),
            "Equal identifiers must hash alike to key the same entry of a response map.");

        Dictionary<CredentialQueryId, string> presentationsByQueryId = new() { [first] = "presentation" };

        Assert.IsTrue(
            presentationsByQueryId.ContainsKey(second),
            "Section 8.1: an identifier over the same id value reaches the same vp_token entry.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1">
    /// OpenID for Verifiable Presentations 1.0, Section 6.1</see>: "The value MUST be a non-empty
    /// string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the
    /// Authorization Request, the same id MUST NOT be present more than once." The class admits
    /// both letter cases as distinct characters, so <c>A</c> and <c>a</c> are two ids, not one
    /// repeated id, and comparing them is ordinal rather than case-insensitive.
    /// </summary>
    [TestMethod]
    public void CredentialQueryIdsDifferingInLetterCaseAreNotEqual()
    {
        CredentialQueryId upper = new("A");
        CredentialQueryId lower = new("a");

        Assert.AreNotEqual(
            upper,
            lower,
            "Section 6.1's character class is ordinal: 'A' and 'a' are different ids.");

        Dictionary<CredentialQueryId, string> presentationsByQueryId = new() { [upper] = "presentation" };

        Assert.IsFalse(
            presentationsByQueryId.ContainsKey(lower),
            "Section 8.1's response map addresses 'A' and 'a' as different entries.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">
    /// OpenID for Verifiable Presentations 1.0, Section 8.1</see>: "the key is the id value used for
    /// a Credential Query in the DCQL query". The identifier renders as that bare id value, so a
    /// message, log line or wire key composed from it carries the value alone and nothing the type
    /// wraps around it.
    /// </summary>
    [TestMethod]
    public void CredentialQueryIdToStringReportsTheBareValue()
    {
        CredentialQueryId identifier = new("pid_2-x");

        Assert.AreEqual(
            "pid_2-x",
            identifier.ToString(),
            "Section 8.1 keys the response on the id value, so the identifier renders as that value.");
        Assert.AreEqual(
            "credential query 'pid_2-x'",
            $"credential query '{identifier}'",
            "An identifier composed into a message carries the bare id value.");
    }
}
