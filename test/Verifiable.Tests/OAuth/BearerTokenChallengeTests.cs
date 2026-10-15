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
        _ = Assert.ThrowsExactly<ArgumentException>(() => BearerTokenChallenge.BuildChallenge());
    }


    /// <summary>§3: <c>error</c> values MUST NOT include characters outside %x20-21 / %x23-5B / %x5D-7E — %x22 is outside.</summary>
    [TestMethod]
    public void ErrorWithDoubleQuoteThrows()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(error: "invalid\"token"));
    }


    /// <summary>§3: control characters are outside the <c>error_description</c> charset.</summary>
    [TestMethod]
    public void ErrorDescriptionWithControlCharacterThrows()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(errorDescription: "line one\nline two"));
    }


    /// <summary>§3: non-ASCII characters are outside the <c>error_description</c> charset.</summary>
    [TestMethod]
    public void ErrorDescriptionWithNonAsciiCharacterThrows()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(errorDescription: "accés refusé"));
    }


    /// <summary>§3: <c>\</c> (%x5C) is outside the scope charset.</summary>
    [TestMethod]
    public void ScopeWithBackslashThrows()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(
            () => BearerTokenChallenge.BuildChallenge(scope: "read\\write"));
    }


    /// <summary>
    /// §3 / RFC 6749 §3.3: the scope list is scope-tokens with single %x20
    /// delimiters — leading, trailing, and consecutive spaces are malformed.
    /// </summary>
    [TestMethod]
    public void ScopeDelimiterShapeIsEnforced()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(() => BearerTokenChallenge.BuildChallenge(scope: " openid"));
        _ = Assert.ThrowsExactly<ArgumentException>(() => BearerTokenChallenge.BuildChallenge(scope: "openid "));
        _ = Assert.ThrowsExactly<ArgumentException>(() => BearerTokenChallenge.BuildChallenge(scope: "openid  profile"));
    }


    /// <summary>Control characters cannot be represented in a quoted-string <c>realm</c>.</summary>
    [TestMethod]
    public void RealmWithControlCharacterThrows()
    {
        _ = Assert.ThrowsExactly<ArgumentException>(
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


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>:
    /// "WWW-Authenticate = #challenge", and the field value "might contain more than one challenge";
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see> names a resource
    /// indicating "support for multiple authentication schemes (i.e., Bearer and DPoP)" in it. The value
    /// <c>Bearer realm="x", DPoP algs="ES256"</c> holds one <c>Bearer</c> challenge, which the parser reads: its
    /// <c>realm</c> is <c>x</c>.
    /// </summary>
    [TestMethod]
    public void TheBearerChallengeOfAChallengeListIsParsed()
    {
        Assert.IsTrue(BearerTokenChallenge.TryParse(
            "Bearer realm=\"x\", DPoP algs=\"ES256\"", out BearerTokenChallengeParameters parameters),
            "The one Bearer challenge of the list is read.");
        Assert.AreEqual("x", parameters.Realm);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.5">RFC 9110 Section 11.5</see>: "a response can have
    /// multiple challenges with the same auth-scheme but with different realms", and neither challenge states which of
    /// them a client is to act on, so the parser's own rule reads a list holding two <c>Bearer</c> challenges as no one
    /// Bearer challenge: <c>Bearer realm="x", Bearer realm="y"</c> is refused.
    /// </summary>
    [TestMethod]
    public void AListHoldingTwoBearerChallengesIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse("Bearer realm=\"x\", Bearer realm=\"y\"", out _));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "All challenges defined by
    /// this specification MUST use the auth-scheme value "Bearer"." A challenge list holding no <c>Bearer</c>
    /// challenge, <c>DPoP algs="ES256", Basic realm="y"</c>, is refused.
    /// </summary>
    [TestMethod]
    public void AListHoldingNoBearerChallengeIsRejected()
    {
        Assert.IsFalse(BearerTokenChallenge.TryParse("DPoP algs=\"ES256\", Basic realm=\"y\"", out _));
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "The scheme name is
    /// DPoP.", with its <c>realm</c>, <c>error</c>, <c>scope</c> and <c>algs</c> parameters ("The value of the parameter
    /// is a space-delimited list of JWS alg (Algorithm) header values") and, by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>, <c>resource_metadata</c>
    /// ("This parameter MAY also be used in WWW-Authenticate responses using authorization schemes other than "Bearer"
    /// [RFC6750], such as the DPoP scheme defined by [RFC9449]."); each parameter once
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>: "each parameter name
    /// MUST only occur once per challenge"), each value a quoted-string (Section 11.5, of the realm: "For historical
    /// reasons, a sender MUST only generate the quoted-string syntax."), and the scheme alone a challenge ("challenge =
    /// auth-scheme [ 1*SP ( token68 / #auth-param ) ]", Section 11.3). The builder writes, for all five parameters,
    /// <c>DPoP realm="r", error="invalid_token", scope="openid profile", algs="ES256 PS256",
    /// resource_metadata="https://rs.example/.well-known/oauth-protected-resource"</c>; for <c>error</c> and
    /// <c>algs</c>, <c>DPoP error="use_dpop_nonce", algs="ES256"</c>; and for none, <c>DPoP</c>. The builder is in
    /// process: its arguments are its input, which no request shapes.
    /// </summary>
    /// <param name="row">Which parameters are given.</param>
    [TestMethod]
    [DataRow(AllParametersRow)]
    [DataRow(ErrorAndAlgorithmsRow)]
    [DataRow(NoParameterRow)]
    public void DpopChallengeIsBuiltWithItsParametersInTheOrderTheBuilderWritesThem(string row)
    {
        (string built, string expected) = row switch
        {
            AllParametersRow => (
                DpopChallenge.BuildChallenge(
                    realm: "r", error: OAuthErrors.InvalidToken, scope: "openid profile", algorithms: ["ES256", "PS256"],
                    resourceMetadata: new Uri("https://rs.example/.well-known/oauth-protected-resource")),
                "DPoP realm=\"r\", error=\"invalid_token\", scope=\"openid profile\", algs=\"ES256 PS256\", "
                + "resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource\""),
            ErrorAndAlgorithmsRow => (
                DpopChallenge.BuildChallenge(error: OAuthErrors.UseDpopNonce, algorithms: ["ES256"]),
                "DPoP error=\"use_dpop_nonce\", algs=\"ES256\""),
            NoParameterRow => (DpopChallenge.BuildChallenge(), "DPoP"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown parameter row.")
        };

        Assert.AreEqual(expected, built);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>, whose attributes the
    /// <c>DPoP</c> challenge names (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section
    /// 7.1</see>): "Values for the "scope" attribute ... MUST NOT include characters outside the set %x21 / %x23-5B /
    /// %x5D-7E for representing scope values and %x20 for delimiters between scope values. Values for the "error" and
    /// "error_description" attributes ... MUST NOT include characters outside the set %x20-21 / %x23-5B / %x5D-7E.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 Section 5.6.4</see>'s quoted-string
    /// for the realm. A value the builder cannot write is the caller's own argument and is refused with
    /// <see cref="ArgumentException"/> naming the parameter: an <c>error</c> holding <c>"</c>; a <c>scope</c> with two SP
    /// between its values; a <c>realm</c> holding U+0001; an algorithm name holding SP, which would split the
    /// space-delimited <c>algs</c> list; a metadata URL holding CR, which no field value carries (RFC 9110 Section 5.5).
    /// The builder is in process: its arguments are its input, which no request shapes.
    /// </summary>
    /// <param name="row">Which value is outside its set.</param>
    [TestMethod]
    [DataRow(ErrorWithQuoteRow)]
    [DataRow(ScopeWithTwoSpacesRow)]
    [DataRow(RealmWithControlRow)]
    [DataRow(AlgorithmWithSpaceRow)]
    [DataRow(MetadataWithCarriageReturnRow)]
    public void DpopChallengeBuilderRefusesAValueOutsideItsCharset(string row)
    {
        (Action Build, string ParameterName) expected = row switch
        {
            ErrorWithQuoteRow => (() => DpopChallenge.BuildChallenge(error: "invalid\"token"), "error"),
            ScopeWithTwoSpacesRow => (() => DpopChallenge.BuildChallenge(scope: "openid  profile"), "scope"),
            RealmWithControlRow => (() => DpopChallenge.BuildChallenge(realm: "r" + (char)0x0001), "realm"),
            AlgorithmWithSpaceRow => (() => DpopChallenge.BuildChallenge(algorithms: ["ES256 PS256"]), "algorithms"),
            MetadataWithCarriageReturnRow => (
                () => DpopChallenge.BuildChallenge(resourceMetadata: new Uri("https://rs.example/a" + (char)0x000D + "b")),
                "resourceMetadata"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown value row.")
        };

        ArgumentException refusal = Assert.ThrowsExactly<ArgumentException>(expected.Build);
        Assert.AreEqual(expected.ParameterName, refusal.ParamName);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "Additional
    /// authentication parameters MAY be used, and unknown parameters MUST be ignored by recipients.", over the challenge
    /// list of <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>:
    /// "WWW-Authenticate = #challenge", whose value "might contain more than one challenge, and each challenge can contain
    /// a comma-separated list of authentication parameters. Furthermore, the header field itself can occur multiple
    /// times." The one <c>DPoP</c> challenge is read from: Figure 15, <c>DPoP algs="ES256 PS256"</c> (the names ES256 and
    /// PS256); Figure 16, <c>DPoP error="invalid_token", error_description="Invalid DPoP key binding", algs="ES256"</c>
    /// (the error and its description); Figure 17, <c>Bearer, DPoP algs="ES256 PS256"</c>; Figure 19's value, the
    /// <c>DPoP</c> challenge after the <c>Bearer</c> one with <c>error="invalid_request"</c>; a <c>DPoP</c> challenge whose
    /// parameters continue on a second field line; and <c>DPoP error="invalid_token", x="use_dpop_nonce"</c>, whose
    /// unknown parameter is not read as the error. The reader is in process: the field lines are its input.
    /// </summary>
    /// <param name="row">Which value is read.</param>
    [TestMethod]
    [DataRow(Figure15Row)]
    [DataRow(Figure16Row)]
    [DataRow(Figure17Row)]
    [DataRow(Figure19Row)]
    [DataRow(ContinuedOnASecondLineRow)]
    [DataRow(UnknownParameterRow)]
    public void DpopChallengeIsReadFromTheChallengeList(string row)
    {
        (IReadOnlyList<string> FieldLines, string? Error, string? ErrorDescription, string[]? Algorithms) expected = row switch
        {
            Figure15Row => (["DPoP algs=\"ES256 PS256\""], null, null, ["ES256", "PS256"]),
            Figure16Row => (["DPoP error=\"invalid_token\", error_description=\"Invalid DPoP key binding\", algs=\"ES256\""],
                OAuthErrors.InvalidToken, "Invalid DPoP key binding", ["ES256"]),
            Figure17Row => (["Bearer, DPoP algs=\"ES256 PS256\""], null, null, ["ES256", "PS256"]),
            Figure19Row => ([
                    "Bearer error=\"invalid_request\", error_description=\"Multiple methods used to include access token\", "
                    + "DPoP algs=\"ES256 PS256\", error=\"invalid_request\", error_description=\"Multiple methods used to include access token\""],
                OAuthErrors.InvalidRequest, "Multiple methods used to include access token", ["ES256", "PS256"]),
            ContinuedOnASecondLineRow => (["DPoP error=\"use_dpop_nonce\"", "algs=\"ES256\""], OAuthErrors.UseDpopNonce, null, ["ES256"]),
            UnknownParameterRow => (["DPoP error=\"invalid_token\", x=\"use_dpop_nonce\""], OAuthErrors.InvalidToken, null, null),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown value row.")
        };

        Assert.IsTrue(DpopChallenge.TryRead(expected.FieldLines, out DpopChallengeParameters parameters), "The one DPoP challenge is read.");
        Assert.AreEqual(expected.Error, parameters.Error);
        Assert.AreEqual(expected.ErrorDescription, parameters.ErrorDescription);
        if(expected.Algorithms is null)
        {
            Assert.IsNull(parameters.Algorithms);

            return;
        }

        Assert.AreSequenceEqual(expected.Algorithms, parameters.Algorithms!.ToArray());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> names the parameters of
    /// the <c>DPoP</c> challenge: "The authentication parameter realm MAY be included", "A scope authentication parameter
    /// MAY be included as defined in [RFC6750], Section 3.", an <c>error</c>, and "An algs parameter ... The value of the
    /// parameter is a space-delimited list of JWS alg (Algorithm) header values"; with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see>, "resource_metadata: The
    /// URL of the protected resource metadata.", which "MAY also be used in WWW-Authenticate responses using authorization
    /// schemes other than "Bearer" [RFC6750], such as the DPoP scheme defined by [RFC9449]."; and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">RFC 9110 Section 11.3</see>, "challenge =
    /// auth-scheme [ 1*SP ( token68 / #auth-param ) ]", under which the scheme alone is a challenge. The reading carries
    /// every parameter the challenge names, and none it does not: from
    /// <c>DPoP realm="r", error="invalid_token", scope="openid profile", algs="ES256 PS256",
    /// resource_metadata="https://rs.example/.well-known/oauth-protected-resource"</c>, the realm <c>r</c>, the error
    /// <c>invalid_token</c>, the scope <c>openid profile</c>, the names ES256 and PS256 and the metadata URL, no
    /// description; from the bare <c>DPoP</c>, a reading with every parameter absent; and from
    /// <c>DPoP algs="ES256  PS256"</c>, whose names two SP separate, the names ES256 and PS256 and nothing else. The
    /// reader is in process: the field lines are its input, which the parser reads as a client receives them.
    /// </summary>
    /// <param name="row">Which value is read.</param>
    [TestMethod]
    [DataRow(AllFiveParametersReadRow)]
    [DataRow(BareSchemeReadRow)]
    [DataRow(DoubledSpacesInAlgsRow)]
    public void DpopChallengeReadingCarriesEveryParameterItNames(string row)
    {
        (string value, DpopChallengeParameters expected) = row switch
        {
            AllFiveParametersReadRow => (
                "DPoP realm=\"r\", error=\"invalid_token\", scope=\"openid profile\", algs=\"ES256 PS256\", "
                + "resource_metadata=\"https://rs.example/.well-known/oauth-protected-resource\"",
                new DpopChallengeParameters(
                    "r", OAuthErrors.InvalidToken, null, "openid profile", ["ES256", "PS256"],
                    new Uri("https://rs.example/.well-known/oauth-protected-resource"))),
            BareSchemeReadRow => ("DPoP", new DpopChallengeParameters(null, null, null, null, null, null)),
            DoubledSpacesInAlgsRow => ("DPoP algs=\"ES256  PS256\"", new DpopChallengeParameters(null, null, null, null, ["ES256", "PS256"], null)),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown value row.")
        };

        Assert.IsTrue(DpopChallenge.TryParse(value, out DpopChallengeParameters parameters), "The one DPoP challenge is read.");
        Assert.AreEqual(expected.Realm, parameters.Realm);
        Assert.AreEqual(expected.Error, parameters.Error);
        Assert.AreEqual(expected.ErrorDescription, parameters.ErrorDescription);
        Assert.AreEqual(expected.Scope, parameters.Scope);
        Assert.AreEqual(expected.ResourceMetadata, parameters.ResourceMetadata);
        if(expected.Algorithms is null)
        {
            Assert.IsNull(parameters.Algorithms);

            return;
        }

        Assert.AreSequenceEqual(expected.Algorithms.ToArray(), parameters.Algorithms!.ToArray());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.5">RFC 9110 Section 11.5</see> lets a response carry
    /// "multiple challenges with the same auth-scheme but with different realms", and reading two <c>DPoP</c> challenges
    /// as no one challenge is the library's own rule (<see cref="DpopChallenge"/>): neither states which of them a client
    /// is to act on. A value outside the quoted-string grammar of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">Section 5.6.4</see> is read as no challenge. The
    /// reading fails with every parameter absent for: <c>DPoP realm="a", DPoP realm="b"</c>; <c>Bearer realm="a"</c>
    /// alone; and <c>DPoP error="invalid_token</c>, its quoted-string unterminated. A <c>resource_metadata</c> is read
    /// by the library's own reading as an absolute http or https URL:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-5.1">RFC 9728 Section 5.1</see> says only
    /// "resource_metadata: The URL of the protected resource metadata.", and the https half rests on
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-1.2">Section 1.2</see>, "Resource Identifier: The
    /// protected resource's resource identifier, which is a URL that uses the https scheme", from which
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-3">Section 3</see> forms the metadata URL "by inserting
    /// a well-known URI string into the protected resource's resource identifier"; so
    /// <c>DPoP error="invalid_token", resource_metadata="ftp://rs.example/metadata"</c> fails the reading. A token68
    /// after the scheme is refused by the library's own rule:
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">RFC 9110 Section 11.3</see> allows one in a
    /// challenge ("challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]"), while the <c>DPoP</c> challenge of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see> is written with
    /// auth-params, so a token68 after the scheme is read as no <c>DPoP</c> challenge and <c>DPoP abc123==</c> fails the
    /// reading. The reader is in process: the field lines are its input.
    /// </summary>
    /// <param name="row">Which value is read.</param>
    [TestMethod]
    [DataRow(TwoDpopChallengesRow)]
    [DataRow(BearerAloneRow)]
    [DataRow(UnterminatedQuotedStringRow)]
    [DataRow(ResourceMetadataNotHttpRow)]
    [DataRow(Token68AfterTheSchemeRow)]
    public void DpopChallengeReadingFailsWhereTheListHoldsNoOneDpopChallenge(string row)
    {
        string value = row switch
        {
            TwoDpopChallengesRow => "DPoP realm=\"a\", DPoP realm=\"b\"",
            BearerAloneRow => "Bearer realm=\"a\"",
            UnterminatedQuotedStringRow => "DPoP error=\"invalid_token",
            ResourceMetadataNotHttpRow => "DPoP error=\"invalid_token\", resource_metadata=\"ftp://rs.example/metadata\"",
            Token68AfterTheSchemeRow => "DPoP abc123==",
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown value row.")
        };

        Assert.IsFalse(DpopChallenge.TryParse(value, out DpopChallengeParameters parameters));
        Assert.IsNull(parameters.Realm);
        Assert.IsNull(parameters.Error);
        Assert.IsNull(parameters.ErrorDescription);
        Assert.IsNull(parameters.Scope);
        Assert.IsNull(parameters.Algorithms);
        Assert.IsNull(parameters.ResourceMetadata);
    }


    /// <summary>The builder row naming all five parameters.</summary>
    private const string AllParametersRow = "all-parameters";

    /// <summary>The builder row naming <c>error</c> and <c>algs</c>.</summary>
    private const string ErrorAndAlgorithmsRow = "error-and-algs";

    /// <summary>The builder row naming no parameter.</summary>
    private const string NoParameterRow = "no-parameter";

    /// <summary>The refusal row whose <c>error</c> holds <c>"</c>.</summary>
    private const string ErrorWithQuoteRow = "error-with-quote";

    /// <summary>The refusal row whose <c>scope</c> holds two SP between its values.</summary>
    private const string ScopeWithTwoSpacesRow = "scope-with-two-spaces";

    /// <summary>The refusal row whose <c>realm</c> holds U+0001.</summary>
    private const string RealmWithControlRow = "realm-with-control";

    /// <summary>The refusal row whose algorithm name holds SP.</summary>
    private const string AlgorithmWithSpaceRow = "algorithm-with-space";

    /// <summary>The refusal row whose metadata URL holds CR.</summary>
    private const string MetadataWithCarriageReturnRow = "metadata-with-carriage-return";

    /// <summary>The reading row of RFC 9449 Figure 15.</summary>
    private const string Figure15Row = "figure-15";

    /// <summary>The reading row of RFC 9449 Figure 16.</summary>
    private const string Figure16Row = "figure-16";

    /// <summary>The reading row of RFC 9449 Figure 17.</summary>
    private const string Figure17Row = "figure-17";

    /// <summary>The reading row of RFC 9449 Figure 19.</summary>
    private const string Figure19Row = "figure-19";

    /// <summary>The reading row whose <c>DPoP</c> challenge continues on a second field line.</summary>
    private const string ContinuedOnASecondLineRow = "continued-on-a-second-line";

    /// <summary>The reading row whose challenge carries an unknown parameter holding <c>use_dpop_nonce</c>.</summary>
    private const string UnknownParameterRow = "unknown-parameter";

    /// <summary>The reading row whose challenge names all five parameters.</summary>
    private const string AllFiveParametersReadRow = "all-five-parameters-read";

    /// <summary>The reading row whose challenge is the scheme alone.</summary>
    private const string BareSchemeReadRow = "bare-scheme-read";

    /// <summary>The reading row whose <c>algs</c> separates its names by two SP.</summary>
    private const string DoubledSpacesInAlgsRow = "doubled-spaces-in-algs";

    /// <summary>The failing row holding two <c>DPoP</c> challenges.</summary>
    private const string TwoDpopChallengesRow = "two-dpop-challenges";

    /// <summary>The failing row holding a <c>Bearer</c> challenge alone.</summary>
    private const string BearerAloneRow = "bearer-alone";

    /// <summary>The failing row whose quoted-string is unterminated.</summary>
    private const string UnterminatedQuotedStringRow = "unterminated-quoted-string";

    /// <summary>The failing row whose <c>resource_metadata</c> is no http or https URL.</summary>
    private const string ResourceMetadataNotHttpRow = "resource-metadata-not-http";

    /// <summary>The failing row carrying a token68 after the scheme.</summary>
    private const string Token68AfterTheSchemeRow = "token68-after-the-scheme";


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>: the field value
    /// "might contain more than one challenge, and each challenge can contain a comma-separated list of authentication
    /// parameters", and <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">Section 11.2</see>: "each
    /// parameter name MUST only occur once per challenge". A value whose unrelated <c>Basic</c> challenge carries five
    /// thousand distinct auth-params, followed by <c>Bearer realm="x", error="invalid_token"</c>, holds one
    /// <c>Bearer</c> challenge, which the parser reads with its attributes.
    /// </summary>
    [TestMethod]
    public void TheBearerChallengeAfterAChallengeOfThousandsOfDistinctParametersIsParsed()
    {
        string unrelated = "Basic " + string.Join(", ", Enumerable.Range(0, 5000).Select(index => $"p{index}=v"));

        Assert.IsTrue(BearerTokenChallenge.TryParse(
            unrelated + ", Bearer realm=\"x\", error=\"invalid_token\"", out BearerTokenChallengeParameters parameters),
            "The Bearer challenge after the thousands of distinct names is read.");
        Assert.AreEqual("x", parameters.Realm);
        Assert.AreEqual(OAuthErrors.InvalidToken, parameters.Error);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>: "the name token is
    /// matched case-insensitively and each parameter name MUST only occur once per challenge". A <c>Basic</c> challenge
    /// of five thousand distinct auth-params that names its first parameter again as <c>P0</c> is outside the grammar,
    /// and the value holding it beside <c>Bearer realm="x"</c> is refused as a whole.
    /// </summary>
    [TestMethod]
    public void AChallengeRepeatingANameAmongThousandsOfParametersIsRejected()
    {
        string unrelated = "Basic " + string.Join(", ", Enumerable.Range(0, 5000).Select(index => $"p{index}=v")) + ", P0=v";

        Assert.IsFalse(BearerTokenChallenge.TryParse(unrelated + ", Bearer realm=\"x\"", out _),
            "A challenge naming a parameter twice among thousands is outside the grammar.");
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
