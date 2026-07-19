using System;
using Verifiable.OAuth;
using Verifiable.OAuth.ProtectedResource;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Spec tests for the RFC 6750 §3 <c>WWW-Authenticate: Bearer</c> challenge
/// builder and parser (<see cref="BearerTokenChallenge"/>). The happy-path
/// cases reproduce §3's own example values verbatim; the rest pin each
/// attribute alone and combined, the round-trip through
/// <see cref="BearerTokenChallenge.TryParse"/>, the §3 charset rejections, the
/// RFC 9728 §5.1 <c>resource_metadata</c> composition, and the auth-param
/// grammar edges (RFC 9110 §11.2).
/// </summary>
[TestClass]
internal sealed class BearerTokenChallengeTests
{
    /// <summary>RFC 6750 §3, first example: a challenge carrying only <c>realm</c>.</summary>
    [TestMethod]
    public void RealmAloneMatchesRfc6750Section3Example()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(realm: "example");

        Assert.AreEqual("Bearer realm=\"example\"", challenge);
    }


    /// <summary>
    /// RFC 6750 §3, second example (as the logical single-line header value):
    /// the expired-token challenge with <c>realm</c>, <c>error</c>, and
    /// <c>error_description</c>.
    /// </summary>
    [TestMethod]
    public void ExpiredTokenChallengeMatchesRfc6750Section3Example()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(
            realm: "example",
            error: OAuthErrors.InvalidToken,
            errorDescription: "The access token expired");

        Assert.AreEqual(
            "Bearer realm=\"example\", error=\"invalid_token\", " +
            "error_description=\"The access token expired\"",
            challenge);
    }


    /// <summary>§3.1: the <c>error</c> attribute alone.</summary>
    [TestMethod]
    public void ErrorAloneIsEmitted()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(error: OAuthErrors.InvalidToken);

        Assert.AreEqual("Bearer error=\"invalid_token\"", challenge);
    }


    /// <summary>§3: the <c>error_description</c> attribute alone.</summary>
    [TestMethod]
    public void ErrorDescriptionAloneIsEmitted()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(
            errorDescription: "The access token expired");

        Assert.AreEqual("Bearer error_description=\"The access token expired\"", challenge);
    }


    /// <summary>§3: the OpenID Connect example scope value, alone.</summary>
    [TestMethod]
    public void ScopeAloneMatchesRfc6750OpenIdExample()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(scope: "openid profile email");

        Assert.AreEqual("Bearer scope=\"openid profile email\"", challenge);
    }


    /// <summary>
    /// §3: the OMAP example scope value exercises the edge of the scope
    /// charset — <c>=</c>, <c>&amp;</c>, and a comma inside the quoted-string —
    /// and must survive the round-trip without splitting on the comma.
    /// </summary>
    [TestMethod]
    public void OmapScopeExampleValueRoundTrips()
    {
        string omapScope = "urn:example:channel=HBO&urn:example:rating=G,PG-13";

        string challenge = BearerTokenChallenge.BuildChallenge(scope: omapScope);

        Assert.AreEqual(
            "Bearer scope=\"urn:example:channel=HBO&urn:example:rating=G,PG-13\"", challenge);
        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters));
        Assert.AreEqual(omapScope, parameters.Scope);
    }


    /// <summary>
    /// RFC 9728 §5.1: <c>resource_metadata</c> alone composes to the same
    /// challenge <see cref="ProtectedResourceChallenge.BuildChallenge"/>
    /// produces — the value formatting is delegated, not restated.
    /// </summary>
    [TestMethod]
    public void ResourceMetadataAloneMatchesProtectedResourceChallenge()
    {
        Uri metadataUrl = new("https://resource.example.com/.well-known/oauth-protected-resource");

        string challenge = BearerTokenChallenge.BuildChallenge(resourceMetadata: metadataUrl);

        Assert.AreEqual(
            "Bearer resource_metadata=\"https://resource.example.com/.well-known/oauth-protected-resource\"",
            challenge);
        Assert.AreEqual(
            ProtectedResourceChallenge.BuildChallenge(WellKnownAuthenticationSchemes.Bearer, metadataUrl),
            challenge);
    }


    /// <summary>All five attributes combine into one header, one scheme, in signature order.</summary>
    [TestMethod]
    public void AllParametersCombinedAppearInSignatureOrder()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(
            realm: "example",
            error: OAuthErrors.InvalidToken,
            errorDescription: "The access token expired",
            scope: "openid profile",
            resourceMetadata: new Uri("https://resource.example.com/.well-known/oauth-protected-resource"));

        Assert.AreEqual(
            "Bearer realm=\"example\", error=\"invalid_token\", " +
            "error_description=\"The access token expired\", scope=\"openid profile\", " +
            "resource_metadata=\"https://resource.example.com/.well-known/oauth-protected-resource\"",
            challenge);
    }


    /// <summary>
    /// §3.1: the <c>insufficient_scope</c> challenge MAY carry the
    /// <c>scope</c> attribute naming the scope necessary to access the
    /// resource — the shape a 403 response uses.
    /// </summary>
    [TestMethod]
    public void InsufficientScopeChallengeCarriesScopeAttribute()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(
            error: OAuthErrors.InsufficientScope,
            scope: "admin");

        Assert.AreEqual("Bearer error=\"insufficient_scope\", scope=\"admin\"", challenge);
    }


    /// <summary>RFC 9110 §5.6.4: <c>"</c> and <c>\</c> in <c>realm</c> are backslash-escaped and unescape on parse.</summary>
    [TestMethod]
    public void RealmQuotedStringSpecialCharactersAreEscapedAndRoundTrip()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(realm: "say \"hi\" \\ bye");

        Assert.AreEqual("Bearer realm=\"say \\\"hi\\\" \\\\ bye\"", challenge);
        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters));
        Assert.AreEqual("say \"hi\" \\ bye", parameters.Realm);
    }


    /// <summary>A round-trip through <see cref="BearerTokenChallenge.TryParse"/> preserves every attribute.</summary>
    [TestMethod]
    public void AllParametersRoundTripThroughTryParse()
    {
        Uri resourceMetadata = new("https://resource.example.com/.well-known/oauth-protected-resource");

        string challenge = BearerTokenChallenge.BuildChallenge(
            realm: "example",
            error: OAuthErrors.InsufficientScope,
            errorDescription: "Higher privileges are required",
            scope: "purchase admin",
            resourceMetadata: resourceMetadata);

        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters));
        Assert.AreEqual("example", parameters.Realm);
        Assert.AreEqual(OAuthErrors.InsufficientScope, parameters.Error);
        Assert.AreEqual("Higher privileges are required", parameters.ErrorDescription);
        Assert.AreEqual("purchase admin", parameters.Scope);
        Assert.AreEqual(resourceMetadata.AbsoluteUri, parameters.ResourceMetadata!.AbsoluteUri);
    }


    /// <summary>
    /// The composed challenge stays readable through the RFC 9728 client-side
    /// reader <see cref="ProtectedResourceChallenge.TryReadResourceMetadata"/>:
    /// one header, one scheme, both the §3 error and the §5.1 pointer.
    /// </summary>
    [TestMethod]
    public void ComposedChallengeIsReadableByProtectedResourceChallengeReader()
    {
        Uri metadataUrl = new("https://rs1.example/.well-known/oauth-protected-resource");

        string challenge = BearerTokenChallenge.BuildChallenge(
            error: OAuthErrors.InvalidToken,
            resourceMetadata: metadataUrl);

        Assert.AreEqual(
            "Bearer error=\"invalid_token\", " +
            "resource_metadata=\"https://rs1.example/.well-known/oauth-protected-resource\"",
            challenge);
        Assert.AreEqual(metadataUrl.OriginalString, ProtectedResourceChallenge.TryReadResourceMetadata(challenge));
        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters));
        Assert.AreEqual(OAuthErrors.InvalidToken, parameters.Error);
        Assert.AreEqual(metadataUrl.AbsoluteUri, parameters.ResourceMetadata!.AbsoluteUri);
    }


    /// <summary>A null or empty string attribute is treated as absent, not emitted empty.</summary>
    [TestMethod]
    public void EmptyStringsAreTreatedAsAbsent()
    {
        string challenge = BearerTokenChallenge.BuildChallenge(
            realm: "", error: OAuthErrors.InvalidToken, errorDescription: "", scope: "");

        Assert.AreEqual("Bearer error=\"invalid_token\"", challenge);
    }


    /// <summary>§3: the scheme MUST be followed by one or more auth-param values — all-absent is rejected.</summary>
    [TestMethod]
    public void AllAbsentThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(() => BearerTokenChallenge.BuildChallenge());
    }


    /// <summary>§3: <c>error</c> values MUST NOT include characters outside %x20-21 / %x23-5B / %x5D-7E — %x22 is outside.</summary>
    [TestMethod]
    public void ErrorWithDoubleQuoteThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(error: "invalid\"token"));
    }


    /// <summary>§3: control characters are outside the <c>error_description</c> charset.</summary>
    [TestMethod]
    public void ErrorDescriptionWithControlCharacterThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(errorDescription: "line one\nline two"));
    }


    /// <summary>§3: non-ASCII characters are outside the <c>error_description</c> charset.</summary>
    [TestMethod]
    public void ErrorDescriptionWithNonAsciiCharacterThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(errorDescription: "accés refusé"));
    }


    /// <summary>§3: <c>\</c> (%x5C) is outside the scope charset.</summary>
    [TestMethod]
    public void ScopeWithBackslashThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(scope: "read\\write"));
    }


    /// <summary>
    /// §3 / RFC 6749 §3.3: the scope list is scope-tokens with single %x20
    /// delimiters — leading, trailing, and consecutive spaces are malformed.
    /// </summary>
    [TestMethod]
    public void ScopeDelimiterShapeIsEnforced()
    {
        Assert.ThrowsExactly<ArgumentException>(() => BearerTokenChallenge.BuildChallenge(scope: " openid"));
        Assert.ThrowsExactly<ArgumentException>(() => BearerTokenChallenge.BuildChallenge(scope: "openid "));
        Assert.ThrowsExactly<ArgumentException>(() => BearerTokenChallenge.BuildChallenge(scope: "openid  profile"));
    }


    /// <summary>Control characters cannot be represented in a quoted-string <c>realm</c>.</summary>
    [TestMethod]
    public void RealmWithControlCharacterThrows()
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(realm: "example\u0007"));
    }


    /// <summary>RFC 9110 §11.2: auth-param values may be tokens, not only quoted-strings.</summary>
    [TestMethod]
    public void TokenFormValuesAreAccepted()
    {
        Assert.IsTrue(BearerTokenChallenge.TryParse(
            "Bearer error=invalid_token", out BearerTokenChallengeParameters parameters));
        Assert.AreEqual(OAuthErrors.InvalidToken, parameters.Error);
    }


    /// <summary>RFC 9110 §11.2: auth-param names compare case-insensitively.</summary>
    [TestMethod]
    public void ParameterNamesCompareCaseInsensitively()
    {
        Assert.IsTrue(BearerTokenChallenge.TryParse(
            "Bearer REALM=\"example\", Error=\"invalid_token\"", out BearerTokenChallengeParameters parameters));
        Assert.AreEqual("example", parameters.Realm);
        Assert.AreEqual(OAuthErrors.InvalidToken, parameters.Error);
    }


    /// <summary>RFC 9110 §11.1: the auth-scheme compares case-insensitively.</summary>
    [TestMethod]
    public void SchemeComparesCaseInsensitively()
    {
        Assert.IsTrue(BearerTokenChallenge.TryParse(
            "bearer realm=\"example\"", out BearerTokenChallengeParameters parameters));
        Assert.AreEqual("example", parameters.Realm);
    }


    /// <summary>RFC 9110 §11.2: bad whitespace around <c>=</c> is tolerated on parse.</summary>
    [TestMethod]
    public void WhitespaceAroundEqualsIsTolerated()
    {
        Assert.IsTrue(BearerTokenChallenge.TryParse(
            "Bearer realm = \"example\"", out BearerTokenChallengeParameters parameters));
        Assert.AreEqual("example", parameters.Realm);
    }


    /// <summary>§3: other auth-param attributes MAY be used — unrecognized ones are ignored.</summary>
    [TestMethod]
    public void UnknownParametersAreIgnored()
    {
        Assert.IsTrue(BearerTokenChallenge.TryParse(
            "Bearer realm=\"example\", nonce=\"n-42\"", out BearerTokenChallengeParameters parameters));
        Assert.AreEqual("example", parameters.Realm);
        Assert.IsNull(parameters.Error);
    }


    /// <summary>§3: all challenges defined by RFC 6750 use the auth-scheme value <c>Bearer</c>.</summary>
    [TestMethod]
    public void NonBearerSchemeIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse("Basic realm=\"example\"", out _));
    }


    /// <summary>§3: the scheme MUST be followed by one or more auth-param values.</summary>
    [TestMethod]
    public void BareSchemeWithoutParametersIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse("Bearer", out _));
        Assert.IsFalse(BearerTokenChallenge.TryParse("Bearer   ", out _));
    }


    /// <summary>§3: the recognized attributes MUST NOT appear more than once.</summary>
    [TestMethod]
    public void DuplicateAttributeIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse(
            "Bearer realm=\"a\", realm=\"b\"", out _));
    }


    /// <summary>An unterminated quoted-string is a malformed challenge.</summary>
    [TestMethod]
    public void UnterminatedQuotedStringIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse("Bearer realm=\"example", out _));
    }


    /// <summary>An attribute name without a value violates the auth-param grammar.</summary>
    [TestMethod]
    public void AttributeWithoutValueIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse("Bearer realm", out _));
        Assert.IsFalse(BearerTokenChallenge.TryParse("Bearer realm=", out _));
    }


    /// <summary>Auth-params are comma-separated — juxtaposed parameters are malformed.</summary>
    [TestMethod]
    public void MissingCommaBetweenParametersIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse(
            "Bearer realm=\"a\" error=\"b\"", out _));
    }


    /// <summary>RFC 9728 §3: the metadata URL is absolute — a relative <c>resource_metadata</c> is unusable.</summary>
    [TestMethod]
    public void RelativeResourceMetadataIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse(
            "Bearer resource_metadata=\"/metadata\"", out _));
    }


    /// <summary>
    /// An absolute but non-http(s) <c>resource_metadata</c> is rejected on every platform. This
    /// pins the scheme check independently of <see cref="RelativeResourceMetadataIsRejected"/>,
    /// which only reaches it on Unix (where a rooted path parses as an absolute <c>file:</c> URI).
    /// </summary>
    [TestMethod]
    public void NonHttpResourceMetadataSchemeIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse(
            "Bearer resource_metadata=\"file:///metadata\"", out _));
    }


    /// <summary>A failed parse yields the all-absent parameters instance.</summary>
    [TestMethod]
    public void FailedParseYieldsAllAbsentParameters()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse(
            "Basic realm=\"example\"", out BearerTokenChallengeParameters parameters));
        Assert.IsNull(parameters.Realm);
        Assert.IsNull(parameters.Error);
        Assert.IsNull(parameters.ErrorDescription);
        Assert.IsNull(parameters.Scope);
        Assert.IsNull(parameters.ResourceMetadata);
    }
}
