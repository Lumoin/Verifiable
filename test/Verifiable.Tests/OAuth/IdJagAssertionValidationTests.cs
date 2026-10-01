using Verifiable.Core.Relations;
using Verifiable.Core.SecurityEvents;
using Verifiable.JCose;
using Verifiable.OAuth.IdJag;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit coverage for <see cref="IdJagAssertionValidation"/> — the §4.4.1 / §9.3 claim rules a
/// Resource Authorization Server applies to a decoded, signature-verified Identity Assertion JWT
/// Authorization Grant (draft-ietf-oauth-identity-assertion-authz-grant). Each test pins one
/// normative rule to its <see cref="IdJagValidationFailureReason"/>.
/// </summary>
[TestClass]
internal sealed class IdJagAssertionValidationTests
{
    private const string ResourceServerIssuer = "https://rs.example.com/";
    private const string IdpIssuer = "https://idp.example.com/";
    private const string ResourceClientId = "resource-client-1";
    private const string Subject = "U019488227";
    private const string GrantedScope = "chat.read chat.history";

    /// <summary>
    /// The party a grant's <c>act</c> claim names as the current actor — the outermost link of an
    /// RFC 8693 §4.1 delegation chain.
    /// </summary>
    private const string CurrentActorSubject = "https://svc.example/agent";

    /// <summary>
    /// The party a nested <c>act</c> claim names — a prior actor, informational history per
    /// RFC 8693 §4.1.
    /// </summary>
    private const string PriorActorSubject = "https://svc.example/first-hop";

    private static DateTimeOffset Now { get; } = DateTimeOffset.FromUnixTimeSeconds(1_311_280_970);
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);

    /// <summary>The MSTest-supplied per-test context whose token the asynchronous validations ride.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Validates <paramref name="payload"/> under <paramref name="rule"/> through
    /// <see cref="IdJagAssertionValidation.ValidateAsync"/> with <see cref="ValidHeader"/>, so the association of
    /// the rule is consulted where the profile hands the claim to it.
    /// </summary>
    /// <param name="payload">The grant's claims.</param>
    /// <param name="rule">The rule applied to the grant's <c>sub_id</c> claim.</param>
    /// <returns>The validation result.</returns>
    private ValueTask<IdJagAssertionValidationResult> ValidateAsync(JwtPayload payload, IdJagSubjectIdentifierRule rule) =>
        IdJagAssertionValidation.ValidateAsync(
            ValidHeader(), payload, ResourceServerIssuer, ResourceClientId, Now, Skew, rule, TestContext.CancellationToken);


    private static JwtHeader ValidHeader() =>
        new(capacity: 1)
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.OauthIdJagJwt
        };


    private static JwtPayload ValidPayload() =>
        new(capacity: 8)
        {
            [WellKnownJwtClaimNames.Iss] = IdpIssuer,
            [WellKnownJwtClaimNames.Sub] = Subject,
            [WellKnownJwtClaimNames.Aud] = ResourceServerIssuer,
            [WellKnownJwtClaimNames.ClientId] = ResourceClientId,
            [WellKnownJwtClaimNames.Jti] = "9e43f81b64a33f20116179",
            [WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Scope] = GrantedScope
        };


    private static IdJagAssertionValidationResult Validate(JwtHeader header, JwtPayload payload) =>
        IdJagAssertionValidation.Validate(header, payload, ResourceServerIssuer, ResourceClientId, Now, Skew);


    [TestMethod]
    public void ValidAssertionPassesAndSurfacesClaims()
    {
        IdJagAssertionValidationResult result = Validate(ValidHeader(), ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.FailureReason);
        Assert.AreEqual(Subject, result.Subject);
        Assert.AreEqual(GrantedScope, result.Scope);
        Assert.AreEqual(IdpIssuer, result.Issuer);
        Assert.AreEqual(ResourceClientId, result.ClientId);
        Assert.HasCount(1, result.Audience);
        Assert.AreEqual(ResourceServerIssuer, result.Audience[0]);
    }


    [TestMethod]
    public void MissingTypIsInvalidType()
    {
        JwtHeader header = new(capacity: 1);

        IdJagAssertionValidationResult result = Validate(header, ValidPayload());

        Assert.AreEqual(IdJagValidationFailureReason.InvalidType, result.FailureReason);
    }


    [TestMethod]
    public void WrongTypIsInvalidType()
    {
        JwtHeader header = new(capacity: 1)
        {
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.AtJwt
        };

        IdJagAssertionValidationResult result = Validate(header, ValidPayload());

        Assert.AreEqual(IdJagValidationFailureReason.InvalidType, result.FailureReason);
    }


    [TestMethod]
    public void MissingIssuerIsMissingIssuer()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Iss);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MissingIssuer, result.FailureReason);
    }


    [TestMethod]
    public void IssuerEqualToResourceServerIsSameTrustDomain()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iss] = ResourceServerIssuer;

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.SameTrustDomain, result.FailureReason);
    }


    [TestMethod]
    public void MissingAudienceIsMissingAudience()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Aud);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MissingAudience, result.FailureReason);
    }


    [TestMethod]
    public void AudienceStringMismatchIsAudienceMismatch()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = "https://other.example.com/";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public void AudienceSingleElementArrayIsAccepted()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new object[] { ResourceServerIssuer };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
    }


    [TestMethod]
    public void AudienceMultiElementArrayIsRejectedEvenWhenOneMatches()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new object[] { ResourceServerIssuer, "https://evil.example.com/" };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public void MissingClientIdIsMissingClientId()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.ClientId);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MissingClientId, result.FailureReason);
    }


    [TestMethod]
    public void ClientIdMismatchIsClientMismatch()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.ClientId] = "some-other-client";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.ClientMismatch, result.FailureReason);
    }


    [TestMethod]
    public void MissingSubjectIsMissingSubject()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Sub);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MissingSubject, result.FailureReason);
    }


    [TestMethod]
    public void MissingExpirationIsMissingExpiration()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Exp);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MissingExpiration, result.FailureReason);
    }


    [TestMethod]
    public void ExpiredAssertionIsExpired()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-5).ToUnixTimeSeconds();

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.Expired, result.FailureReason);
    }


    [TestMethod]
    public void NotYetValidAssertionIsNotYetValid()
    {
        //nbf is in the future (beyond skew) but still before exp (Now+5min from the baseline), so the
        //window is consistent — it simply has not opened yet.
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = Now.AddMinutes(2).ToUnixTimeSeconds();

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.NotYetValid, result.FailureReason);
    }


    [TestMethod]
    public void ExpiryAtOrBeforeIssuedAtIsInconsistent()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-1).ToUnixTimeSeconds();

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.InconsistentTemporalClaims, result.FailureReason);
    }


    [TestMethod]
    public void ExpiryAtOrBeforeNotBeforeIsInconsistent()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(2).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Nbf] = Now.AddMinutes(4).ToUnixTimeSeconds();

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.InconsistentTemporalClaims, result.FailureReason);
    }


    [TestMethod]
    public void NonNumericExpirationIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Exp] = "not-a-timestamp";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.InconsistentTemporalClaims, result.FailureReason);
    }


    [TestMethod]
    public void NonNumericNotBeforeIsRejected()
    {
        //A present-but-malformed nbf must not be silently ignored — that would suppress the
        //not-yet-valid check.
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = "soon";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.InconsistentTemporalClaims, result.FailureReason);
    }


    [TestMethod]
    public void AudienceMultiElementArrayWithNonStringExtraIsRejected()
    {
        //Regression guard for the audience-injection fail-open: a non-string extra element must NOT be
        //filtered out to collapse the array to a single accepted entry.
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new object[] { ResourceServerIssuer, 123L };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public void AudienceSingleNonStringElementIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new object[] { 123L };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public void AudienceEmptyArrayIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = Array.Empty<object>();

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public void AudienceEmptyStringIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = string.Empty;

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public void ResourceStringClaimIsSurfaced()
    {
        JwtPayload payload = ValidPayload();
        payload["resource"] = "https://api.chat.example/files";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.HasCount(1, result.Resource);
        Assert.AreEqual("https://api.chat.example/files", result.Resource[0]);
    }


    [TestMethod]
    public void ResourceArrayClaimIsSurfaced()
    {
        JwtPayload payload = ValidPayload();
        payload["resource"] = new object[] { "https://api.chat.example/files", "https://api.chat.example/messages" };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.HasCount(2, result.Resource);
        Assert.AreEqual("https://api.chat.example/files", result.Resource[0]);
        Assert.AreEqual("https://api.chat.example/messages", result.Resource[1]);
    }


    [TestMethod]
    public void AbsentResourceClaimSurfacesEmpty()
    {
        IdJagAssertionValidationResult result = Validate(ValidHeader(), ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsEmpty(result.Resource);
    }


    [TestMethod]
    public void AuthorizationDetailsClaimIsSurfaced()
    {
        JwtPayload payload = ValidPayload();
        payload["authorization_details"] = new List<object>
        {
            new Dictionary<string, object>(StringComparer.Ordinal) { ["type"] = "chat_read" }
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNotNull(result.AuthorizationDetails);
        Assert.HasCount(1, result.AuthorizationDetails);
    }


    [TestMethod]
    public void AbsentAuthorizationDetailsSurfacesNull()
    {
        IdJagAssertionValidationResult result = Validate(ValidHeader(), ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.AuthorizationDetails);
    }


    /// <summary>
    /// A present <c>authorization_details</c> claim that is not a JSON array is refused, not read as absent.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.4.1</see>:
    /// "If the authorization_details claim is present, the Resource Authorization Server MUST parse it as a
    /// JSON array and process each authorization detail object according to [RFC9396]."
    /// </summary>
    [TestMethod]
    public void NonArrayAuthorizationDetailsIsMalformed()
    {
        JwtPayload payload = ValidPayload();
        payload["authorization_details"] = "not-an-array";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedAuthorizationDetails, result.FailureReason);
        Assert.AreEqual("The assertion authorization_details claim is not a JSON array.", result.FailureDescription);
    }


    /// <summary>
    /// A <c>resource</c> array with an element that is not a JSON string is refused whole, not read with the
    /// element dropped.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.4.1</see>:
    /// "If the resource claim is present, the Resource Authorization Server MUST process it according to
    /// Section 2 of [RFC8707]." <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see>:
    /// "Its value MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]."
    /// </summary>
    [TestMethod]
    public void ResourceArrayWithANonStringElementIsMalformedResource()
    {
        JwtPayload payload = ValidPayload();
        payload["resource"] = new object[] { "https://api.chat.example/files", 123L };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedResource, result.FailureReason);
        Assert.AreEqual(
            "The assertion resource claim is not an absolute URI (RFC 3986 section 4.3) without a fragment, or an array of such values.",
            result.FailureDescription);
    }


    /// <summary>
    /// A <c>resource</c> claim outside the resource indicator grammar, or outside the claim's two shapes, is
    /// refused: a value with a fragment, a host naming the Kelvin sign (U+212A), a malformed percent triplet, an
    /// empty scheme, an <c>https</c> value with a userinfo, the empty string, the empty array, a number, a
    /// boolean, an object, a JSON <c>null</c>, and an array holding a <c>null</c> beside a valid value.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 Section 2</see>: "Its value MUST be
    /// an absolute URI, as specified by Section 4.3 of [RFC3986]. The URI MUST NOT include a fragment
    /// component."
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>
    /// names the claim's shapes: "(either a single URI or an array of URIs)".
    /// The userinfo case is refused under
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-4.2.4">RFC 9110 Section 4.2.4</see>: "Before
    /// making use of an "http" or "https" URI reference received from an untrusted source, a recipient SHOULD
    /// parse for userinfo and treat its presence as an error; it is likely being used to obscure the authority
    /// for the sake of phishing attacks."
    /// Refusing the empty string and the empty array is this library's fail-closed reading: no sentence of
    /// Section 3.1 or
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// states it.
    /// </summary>
    /// <param name="caseName">The malformed value the claim carries.</param>
    [TestMethod]
    [DataRow("fragment", DisplayName = "a value with a fragment")]
    [DataRow("nonAsciiHost", DisplayName = "a host naming the Kelvin sign")]
    [DataRow("malformedTriplet", DisplayName = "a malformed percent triplet")]
    [DataRow("emptyScheme", DisplayName = "an empty scheme")]
    [DataRow("httpsUserinfo", DisplayName = "an https value with a userinfo")]
    [DataRow("emptyString", DisplayName = "the empty string")]
    [DataRow("emptyArray", DisplayName = "the empty array")]
    [DataRow("number", DisplayName = "a number")]
    [DataRow("boolean", DisplayName = "a boolean")]
    [DataRow("object", DisplayName = "an object")]
    [DataRow("jsonNull", DisplayName = "a JSON null")]
    [DataRow("arrayHoldingNull", DisplayName = "an array holding a null")]
    public void AResourceClaimOutsideTheGrammarIsMalformedResource(string caseName)
    {
        object? resource = caseName switch
        {
            "fragment" => "https://api.example.com/x#frag",
            "nonAsciiHost" => "https://" + char.ConvertFromUtf32(0x212A) + "eycloak.example/",
            "malformedTriplet" => "https://api.example.com/%GG",
            "emptyScheme" => ":foo",
            "httpsUserinfo" => "https://user@api.example.com/",
            "emptyString" => string.Empty,
            "emptyArray" => Array.Empty<object>(),
            "number" => 5L,
            "boolean" => true,
            "object" => new Dictionary<string, object>(StringComparer.Ordinal) { ["uri"] = "https://api.example.com/files" },
            "jsonNull" => null,
            "arrayHoldingNull" => new object?[] { "https://api.example.com/files", null },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        //The payload indexer stores a JSON null as the library's decoder does: a present member whose value is null.
        JwtPayload payload = ValidPayload();
        payload["resource"] = resource!;

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedResource, result.FailureReason);
        Assert.AreEqual(
            "The assertion resource claim is not an absolute URI (RFC 3986 section 4.3) without a fragment, or an array of such values.",
            result.FailureDescription);
    }


    /// <summary>
    /// Every accepted <c>resource</c> value is surfaced with its scheme and host lowered and its other parts as
    /// sent, in the order given, for a single string and for an array.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-6.2.2.1">RFC 3986 Section 6.2.2.1</see>: "When
    /// a URI uses components of the generic syntax, the component syntax equivalence rules always apply;
    /// namely, that the scheme and host are case-insensitive and therefore should be normalized to lowercase."
    /// </summary>
    /// <param name="caseName">The shape of the claim: <c>string</c> or <c>array</c>.</param>
    [TestMethod]
    [DataRow("string", DisplayName = "a single string")]
    [DataRow("array", DisplayName = "an array of two strings")]
    public void AResourceClaimIsFoldedAtTheRedeem(string caseName)
    {
        (object Sent, string[] Expected) foldCase = caseName switch
        {
            "string" => ("HTTPS://API.CHAT.EXAMPLE/Files", ["https://api.chat.example/Files"]),
            "array" => (new object[] { "HTTPS://A.EXAMPLE/x", "https://b.example/Y" }, ["https://a.example/x", "https://b.example/Y"]),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload["resource"] = foldCase.Sent;

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreSequenceEqual(foldCase.Expected, result.Resource);
    }


    /// <summary>
    /// A grant without a <c>jti</c>, or with one of white space only, is refused.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "jti: REQUIRED - Unique ID of this JWT as defined in Section 4.1.7 of [RFC7519]."
    /// Refusing a <c>jti</c> of white space only is this library's fail-closed reading: no sentence of Section 3.1
    /// or
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">Section 4.4.1</see>
    /// states it.
    /// </summary>
    /// <param name="caseName">The claim's shape: <c>absent</c> or <c>whiteSpace</c>.</param>
    [TestMethod]
    [DataRow("absent", DisplayName = "no jti")]
    [DataRow("whiteSpace", DisplayName = "a jti of white space only")]
    public void AMissingJtiIsRefused(string caseName)
    {
        string? jti = caseName switch
        {
            "absent" => null,
            "whiteSpace" => " ",
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Jti);
        if(jti is not null)
        {
            payload[WellKnownJwtClaimNames.Jti] = jti;
        }

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MissingJti, result.FailureReason);
        Assert.AreEqual("The assertion is missing the jti claim.", result.FailureDescription);
    }


    /// <summary>
    /// A grant without an <c>iat</c> is refused.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-3.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 3.1</see>:
    /// "iat: REQUIRED - as defined in Section 4.1.6 of [RFC7519]."
    /// </summary>
    [TestMethod]
    public void AMissingIssuedAtIsRefused()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Iat);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MissingIssuedAt, result.FailureReason);
        Assert.AreEqual("The assertion is missing the iat claim.", result.FailureDescription);
    }


    /// <summary>
    /// A present <c>iat</c> that is not a number is refused with the time claims' reason, not read as absent.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 Section 4.1.6</see>: "Its value
    /// MUST be a number containing a NumericDate value."
    /// </summary>
    [TestMethod]
    public void NonNumericIssuedAtIsInconsistent()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = "soon";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.InconsistentTemporalClaims, result.FailureReason);
        Assert.AreEqual("The assertion iat claim is not a numeric timestamp.", result.FailureDescription);
    }


    /// <summary>
    /// An <c>aud</c> that differs from the Resource Authorization Server's issuer only in the case of its scheme
    /// and host is refused: the grant's own <c>aud</c> is compared as signed, character for character.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 3: "In the
    /// absence of an application profile specifying otherwise, compliant applications MUST compare the audience
    /// values using the Simple String Comparison method defined in Section 6.2.1 of RFC 3986 [RFC3986]."
    /// </summary>
    [TestMethod]
    public void AnAudienceDifferingFromTheIssuerOnlyInCaseIsAudienceMismatch()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = "HTTPS://RS.EXAMPLE.COM/";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    /// <summary>
    /// A Resource Authorization Server whose issuer is spelled with capitals in its host accepts a grant whose
    /// <c>aud</c> carries the same spelling, and surfaces that <c>aud</c> as signed, not folded.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 3: "In the
    /// absence of an application profile specifying otherwise, compliant applications MUST compare the audience
    /// values using the Simple String Comparison method defined in Section 6.2.1 of RFC 3986 [RFC3986]."
    /// </summary>
    [TestMethod]
    public void AnIssuerSpelledWithCapitalsAcceptsTheSameAudienceAsSigned()
    {
        const string capitalIssuer = "https://RS.Example.COM/";
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = capitalIssuer;

        IdJagAssertionValidationResult result = IdJagAssertionValidation.Validate(
            ValidHeader(), payload, capitalIssuer, ResourceClientId, Now, Skew);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.HasCount(1, result.Audience);
        Assert.AreEqual(capitalIssuer, result.Audience[0]);
    }


    /// <summary>
    /// A present <c>scope</c> claim that is not a JSON string, or whose value breaks the scope grammar, is
    /// refused: a number, a JSON <c>null</c>, the empty string, a doubled space, a tab, a leading space, a
    /// trailing space, a quotation mark (%x22), a reverse solidus (%x5C), the delete character (%x7F) and the
    /// Kelvin sign (U+212A), a code point above %x7E. Refusing the grant for a malformed scope claim, rather than
    /// reading the claim as absent, is decided by this library.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04#section-4.4.1">draft-ietf-oauth-identity-assertion-authz-grant-04 Section 4.4.1</see>:
    /// "If the scope claim is present, the Resource Authorization Server MUST process it according to Section 3.3
    /// of [RFC6749]."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 Section 3.3</see>: "scope =
    /// scope-token *( SP scope-token )" and "scope-token = 1*( %x21 / %x23-5B / %x5D-7E )".
    /// </summary>
    /// <param name="caseName">The malformed value the claim carries.</param>
    [TestMethod]
    [DataRow("number", DisplayName = "a number")]
    [DataRow("jsonNull", DisplayName = "a JSON null")]
    [DataRow("emptyString", DisplayName = "the empty string")]
    [DataRow("doubledSpace", DisplayName = "a doubled space")]
    [DataRow("tab", DisplayName = "a tab")]
    [DataRow("leadingSpace", DisplayName = "a leading space")]
    [DataRow("trailingSpace", DisplayName = "a trailing space")]
    [DataRow("quotationMark", DisplayName = "a quotation mark")]
    [DataRow("reverseSolidus", DisplayName = "a reverse solidus")]
    [DataRow("deleteCharacter", DisplayName = "the delete character")]
    [DataRow("kelvinSign", DisplayName = "the Kelvin sign")]
    public void AMalformedScopeClaimIsMalformedScope(string caseName)
    {
        object? scope = caseName switch
        {
            "number" => 123L,
            "jsonNull" => null,
            "emptyString" => string.Empty,
            "doubledSpace" => "a  b",
            "tab" => "a" + char.ConvertFromUtf32(0x0009) + "b",
            "leadingSpace" => " a",
            "trailingSpace" => "a ",
            "quotationMark" => "a" + char.ConvertFromUtf32(0x0022) + "b",
            "reverseSolidus" => "a" + char.ConvertFromUtf32(0x5C) + "b",
            "deleteCharacter" => "a" + char.ConvertFromUtf32(0x7F) + "b",
            "kelvinSign" => "a" + char.ConvertFromUtf32(0x212A) + "b",
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Scope] = scope!;

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedScope, result.FailureReason);
        Assert.AreEqual(
            "The assertion scope claim is not a space-delimited list of scope tokens (RFC 6749 section 3.3).",
            result.FailureDescription);
    }


    /// <summary>
    /// A <c>scope</c> claim of one token made of the edges of the token set is surfaced as
    /// <see cref="IdJagAssertionValidationResult.Scope"/> as signed: <c>!#[]~</c> (%x21, %x23, %x5B, %x5D and
    /// %x7E) and <c>!</c> alone.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 Section 3.3</see>: "scope =
    /// scope-token *( SP scope-token )" and "scope-token = 1*( %x21 / %x23-5B / %x5D-7E )".
    /// </summary>
    /// <param name="scope">The scope claim's value.</param>
    [TestMethod]
    [DataRow("!#[]~", DisplayName = "the token of the set's edges")]
    [DataRow("!", DisplayName = "the token of %x21 alone")]
    public void AScopeTokenAtTheEdgesOfTheTokenSetIsSurfaced(string scope)
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Scope] = scope;

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreEqual(scope, result.Scope);
    }


    [TestMethod]
    public void ConfirmationKeyThumbprintIsSurfaced()
    {
        const string thumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
        JwtPayload payload = ValidPayload();
        payload["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal) { ["jkt"] = thumbprint };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreEqual(thumbprint, result.ConfirmationKeyThumbprint);
    }


    [TestMethod]
    public void AbsentConfirmationSurfacesNullThumbprint()
    {
        IdJagAssertionValidationResult result = Validate(ValidHeader(), ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.ConfirmationKeyThumbprint);
    }


    [TestMethod]
    public void ConfirmationWithEmptyThumbprintIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal) { ["jkt"] = string.Empty };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedConfirmation, result.FailureReason);
    }


    [TestMethod]
    public void ConfirmationWithNonStringThumbprintIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal) { ["jkt"] = 1234L };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedConfirmation, result.FailureReason);
    }


    [TestMethod]
    public void ConfirmationWithoutJktMemberIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload["cnf"] = new Dictionary<string, object>(StringComparer.Ordinal);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedConfirmation, result.FailureReason);
    }


    /// <summary>
    /// ID-JAG §3.1: "act: OPTIONAL - Actor claim as defined in Section 4.1 of [RFC8693]. When
    /// present, this claim identifies the actor that is acting on behalf of the subject (sub)." The
    /// grant's chain is surfaced whole — the outermost object naming the current actor with the
    /// prior actor beneath it, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>.
    /// </summary>
    [TestMethod]
    public void ActorChainIsSurfacedWhole()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = CurrentActorSubject,
            [WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.Sub] = PriorActorSubject
            }
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNotNull(result.Act);
        Assert.AreEqual(CurrentActorSubject, (string)result.Act[WellKnownJwtClaimNames.Sub]);
        IReadOnlyDictionary<string, object> nested =
            (IReadOnlyDictionary<string, object>)result.Act[WellKnownJwtClaimNames.Act];
        Assert.AreEqual(PriorActorSubject, (string)nested[WellKnownJwtClaimNames.Sub]);
    }


    /// <summary>
    /// ID-JAG §3.1 makes <c>act</c> OPTIONAL, so a grant that records no delegation surfaces no
    /// chain — the declined half of the capability, distinguished from a malformed claim by the
    /// claim simply not being on the wire.
    /// </summary>
    [TestMethod]
    public void AbsentActorSurfacesNull()
    {
        IdJagAssertionValidationResult result = Validate(ValidHeader(), ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.Act);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: "The
    /// 'act' claim value is a JSON object." A value that is not an object identifies no actor, and
    /// admitting the grant with the claim dropped would present a delegated grant as an undelegated
    /// one — so the grant is refused instead.
    /// </summary>
    [TestMethod]
    public void NonObjectActorIsMalformedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Act] = "https://svc.example/agent";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedActor, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: the
    /// members of the <c>act</c> object "are claims that identify the actor". An object naming no
    /// <c>sub</c> identifies nobody, so no current actor can be established.
    /// </summary>
    [TestMethod]
    public void ActorWithoutSubjectIsMalformedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedActor, result.FailureReason);
    }


    /// <summary>
    /// An actor whose <c>sub</c> is not a string names no party either — the identity members of an
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> actor
    /// object are claim values that identify it, and a number is not an identifier this grant can
    /// compare a redeeming client against.
    /// </summary>
    [TestMethod]
    public void ActorWithNonStringSubjectIsMalformedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = 1234L
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedActor, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: "The
    /// nested 'act' claims serve as a history trail that connects the initial request and subject
    /// through the various delegation steps undertaken before reaching the current actor." A nested
    /// link naming no actor breaks that trail, so the whole chain is malformed rather than silently
    /// truncated at the last readable level.
    /// </summary>
    [TestMethod]
    public void NestedActorWithoutSubjectIsMalformedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = CurrentActorSubject,
            [WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedActor, result.FailureReason);
    }


    /// <summary>
    /// A delegation chain holds one link per hop actually taken
    /// (<see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>), so a
    /// chain nested deeper than the validator's read bound describes no reachable delegation and is
    /// refused — bounding the work a caller-built grant can drive without ever accepting a chain the
    /// validator has not read whole.
    /// </summary>
    [TestMethod]
    public void ActorChainDeeperThanTheReadBoundIsMalformedActor()
    {
        //Seventeen links: one more than the deepest chain the validator reads.
        Dictionary<string, object> chain = new(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = PriorActorSubject
        };
        for(int depth = 0; depth < 16; ++depth)
        {
            chain = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.Sub] = $"{CurrentActorSubject}/{depth}",
                [WellKnownJwtClaimNames.Act] = chain
            };
        }

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Act] = chain;

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedActor, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: the
    /// <c>may_act</c> members "identify the party that is asserted as being eligible to act for the
    /// party identified by the JWT containing the claim", and "the combination of the two claims
    /// 'iss' and 'sub' are sometimes necessary to uniquely identify an authorized actor" — both
    /// members are surfaced so the redemption can enforce the combination.
    /// </summary>
    [TestMethod]
    public void AuthorizedActorIsSurfaced()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.MayAct] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = CurrentActorSubject,
            [WellKnownJwtClaimNames.Iss] = ResourceServerIssuer
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNotNull(result.MayAct);
        Assert.AreEqual(CurrentActorSubject, (string)result.MayAct[WellKnownJwtClaimNames.Sub]);
        Assert.AreEqual(ResourceServerIssuer, (string)result.MayAct[WellKnownJwtClaimNames.Iss]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see> states who
    /// may act only when the claim is present; a grant carrying no <c>may_act</c> surfaces none and
    /// constrains the acting party in no way.
    /// </summary>
    [TestMethod]
    public void AbsentAuthorizedActorSurfacesNull()
    {
        IdJagAssertionValidationResult result = Validate(ValidHeader(), ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.MayAct);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: "The
    /// claim value is a JSON object." A non-object <c>may_act</c> is refused rather than read as "no
    /// constraint", because reducing an unreadable authorized-actor statement to no constraint
    /// erases the very restriction the grant's issuer placed on who may act.
    /// </summary>
    [TestMethod]
    public void NonObjectAuthorizedActorIsMalformedAuthorizedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.MayAct] = CurrentActorSubject;

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedAuthorizedActor, result.FailureReason);
    }


    /// <summary>
    /// An authorized-actor object naming neither a <c>sub</c> nor an <c>iss</c> identifies no party,
    /// so it authorizes none — the members of an
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>
    /// <c>may_act</c> object exist to "identify the party that is asserted as being eligible to
    /// act", and an object identifying nobody is refused rather than treated as unconstrained.
    /// </summary>
    [TestMethod]
    public void AuthorizedActorNamingNoPartyIsMalformedAuthorizedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.MayAct] = new Dictionary<string, object>(StringComparer.Ordinal);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedAuthorizedActor, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: "claims
    /// within the 'act' claim pertain only to the identity of the actor and are not relevant to the
    /// validity of the containing JWT in the same manner as the top-level claims. Consequently,
    /// non-identity claims (e.g., 'exp', 'nbf', and 'aud') are not meaningful when used within an
    /// 'act' claim and are therefore not used." An actor carrying a long-past <c>exp</c> therefore
    /// neither invalidates the grant nor is treated as a validity input.
    /// </summary>
    [TestMethod]
    public void NonIdentityMembersInsideActorAreNotValidityInputs()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = CurrentActorSubject,
            [WellKnownJwtClaimNames.Exp] = Now.AddDays(-30).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Aud] = "https://elsewhere.example.com/"
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreEqual(CurrentActorSubject, (string)result.Act![WellKnownJwtClaimNames.Sub]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: "the
    /// combination of the two claims 'iss' and 'sub' might be necessary to uniquely identify an actor."
    /// An <c>iss</c> present as something other than an identifier states half of that combination
    /// unreadably. The chain is copied verbatim onto the access token the redemption would issue, and
    /// <see cref="Verifiable.OAuth.JwsAccessTokenValidator"/> refuses exactly this shape when a resource server reads
    /// that token — so accepting it here would mint a token no resource can ever validate.
    /// </summary>
    [TestMethod]
    public void ActorWithNonStringIssuerIsMalformedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = CurrentActorSubject,
            [WellKnownJwtClaimNames.Iss] = 1234L
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedActor, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: "the
    /// combination of the two claims 'iss' and 'sub' are sometimes necessary to uniquely identify an
    /// authorized actor." A <c>may_act</c> whose <c>iss</c> is not an identifier states a pair only
    /// half of which can be read, and ignoring the unreadable half would widen the authorization to
    /// every namespace instead of the one the claim names — so the grant is refused.
    /// </summary>
    [TestMethod]
    public void AuthorizedActorWithNonStringIssuerIsMalformedAuthorizedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.MayAct] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = CurrentActorSubject,
            [WellKnownJwtClaimNames.Iss] = 1234L
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedAuthorizedActor, result.FailureReason);
    }


    /// <summary>
    /// The mirror of the same <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693
    /// §4.4</see> pair rule: a <c>may_act</c> whose <c>sub</c> is not an identifier is refused rather
    /// than read as an issuer-only authorization, which would let every client of the named issuer act
    /// where the claim named exactly one.
    /// </summary>
    [TestMethod]
    public void AuthorizedActorWithNonStringSubjectIsMalformedAuthorizedActor()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.MayAct] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = 1234L,
            [WellKnownJwtClaimNames.Iss] = ResourceServerIssuer
        };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MalformedAuthorizedActor, result.FailureReason);
    }


    /// <summary>
    /// The text of an <see cref="IdJagSubjectContext"/> names the grant's issuer and whether a tenant is
    /// present, and neither the subject's value nor the tenant's value: those two values can identify a person,
    /// so they stay out of every text a log or a trace receives. The rule is this library's; no clause of a
    /// specification states it.
    /// </summary>
    /// <param name="tenant">The context's tenant, or <see langword="null"/> for a grant that carries none.</param>
    /// <param name="expectedPresence">The words that state whether a tenant is present.</param>
    [TestMethod]
    [DataRow("tenant-acme", "HasTenant=True", DisplayName = "a context with a tenant")]
    [DataRow(null, "HasTenant=False", DisplayName = "a context without a tenant")]
    public void TheSubjectContextRendersItsIssuerAndNeitherItsSubjectNorItsTenant(string? tenant, string expectedPresence)
    {
        IdJagSubjectContext context = new()
        {
            Issuer = IdpIssuer,
            Subject = Subject,
            Tenant = tenant
        };

        string text = context.ToString();

        Assert.Contains(IdpIssuer, text);
        Assert.DoesNotContain(Subject, text);
        if(tenant is not null)
        {
            Assert.DoesNotContain(tenant, text);
        }

        Assert.Contains(expectedPresence, text);
    }


    /// <summary>
    /// The text of an <see cref="IdJagAssertionValidationResult"/> names whether it is valid, its failure
    /// reason, the grant's issuer, and whether a tenant, a subject identifier and a comparison are present, and
    /// none of the subject, the tenant, the audience subject or the SAML NameID: those values can identify a
    /// person, so they stay out of every text a log or a trace receives. The rule is this library's; no clause
    /// of a specification states it. The successful result, which carries the subject, the tenant, the audience
    /// subject and the SAML NameID, proves that no personal identifier is rendered; the failed result, which holds
    /// no subject, tenant or identifier of its own, proves the shape of the text.
    /// </summary>
    /// <param name="caseName">The result rendered: <c>success</c> or <c>failure</c>.</param>
    [TestMethod]
    [DataRow("success", DisplayName = "a successful result carrying personal identifiers")]
    [DataRow("failure", DisplayName = "a result refused by the comparison")]
    public void TheValidationResultRendersNoPersonalIdentifier(string caseName)
    {
        string tenant = "tenant-acme";
        string audienceSubject = "rs-account-7";
        SamlNameIdSubjectIdentifier samlIdentifier = new()
        {
            Issuer = "https://idp.example.com/saml",
            NameId = "alice@example.com"
        };

        IdJagSubjectContext reference = new()
        {
            Issuer = IdpIssuer,
            Subject = Subject,
            Tenant = tenant
        };

        ComparisonRecord<SubjectIdentifier, IdJagSubjectContext> comparison = new()
        {
            Relation = ComparisonRelation.Equal,
            Outcome = ComparisonOutcome.Fails,
            Basis = ComparisonBasis.ApplicationRule,
            Decision = ComparisonDecision.Deny,
            Candidate = samlIdentifier.ToSubjectIdentifier(),
            Reference = reference
        };

        IdJagAssertionValidationResult result = caseName switch
        {
            "success" => new IdJagAssertionValidationResult
            {
                Subject = Subject,
                Issuer = IdpIssuer,
                Tenant = tenant,
                AudienceSubject = audienceSubject,
                SubjectIdentifier = samlIdentifier.ToSubjectIdentifier(),
                SamlNameIdSubjectIdentifier = samlIdentifier
            },
            "failure" => IdJagAssertionValidationResult.Failure(
                IdJagValidationFailureReason.SubjectIdentifierMismatch,
                "The assertion sub_id claim does not identify the End-User the grant names.") with
            {
                SubjectIdentifierComparison = comparison
            },
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        string text = result.ToString();

        Assert.DoesNotContain(Subject, text);
        Assert.DoesNotContain(tenant, text);
        Assert.DoesNotContain(audienceSubject, text);
        Assert.DoesNotContain(samlIdentifier.NameId, text);
        if(caseName == "success")
        {
            Assert.Contains("IsValid=True", text);
            Assert.Contains(IdpIssuer, text);
            Assert.Contains("HasTenant=True", text);
            Assert.Contains("HasSubjectIdentifier=True", text);
        }
        else
        {
            Assert.Contains("IsValid=False", text);
            Assert.Contains("Reason=SubjectIdentifierMismatch", text);
            Assert.Contains("HasComparison=True", text);
        }
    }


    /// <summary>
    /// A rule keeps its own copy of the formats it accepts: a format added to the set the rule was built from
    /// does not reach a rule already in use, so an <c>email</c> claim under a required <c>sub_id</c> is an
    /// unsupported format even after the caller's set gains <c>email</c>. The rule is this library's; no clause
    /// of a specification states it.
    /// </summary>
    [TestMethod]
    public async Task TheRuleKeepsItsOwnCopyOfTheAcceptedFormats()
    {
        HashSet<string> acceptedFormats = new(StringComparer.Ordinal) { "saml-nameid" };
        IdJagSubjectIdentifierRule rule = new()
        {
            Presence = IdJagSubjectIdentifierPresence.Required,
            AcceptedFormats = acceptedFormats
        };
        _ = acceptedFormats.Add("email");

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.SubId] = SubjectIdentifier.Email("alice@example.com").ToWireObject();

        IdJagAssertionValidationResult result = await ValidateAsync(payload, rule).ConfigureAwait(false);

        Assert.AreEqual(IdJagValidationFailureReason.UnsupportedSubjectIdentifierFormat, result.FailureReason);
    }


    /// <summary>
    /// A rule compares the formats it accepts by their exact spelling: a set built with a comparer that ignores
    /// case and holding <c>EMAIL</c> becomes a set that holds <c>EMAIL</c> and not <c>email</c>, so an
    /// <c>email</c> claim under a required <c>sub_id</c> is an unsupported format.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 Section 3</see>: "A Subject
    /// Identifier MUST conform to a specific Identifier Format and MUST contain a "format" member whose value is
    /// the name of that Identifier Format." The ordinal comparison of that name is this library's rule; no
    /// sentence of a specification states it.
    /// </summary>
    [TestMethod]
    public async Task TheRuleComparesAcceptedFormatsByExactSpelling()
    {
        IdJagSubjectIdentifierRule rule = new()
        {
            Presence = IdJagSubjectIdentifierPresence.Required,
            AcceptedFormats = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "EMAIL" }
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.SubId] = SubjectIdentifier.Email("alice@example.com").ToWireObject();

        IdJagAssertionValidationResult result = await ValidateAsync(payload, rule).ConfigureAwait(false);

        //The set's own lookup is asked, so its comparer decides the answer.
        bool isLowerCaseSpellingAccepted = rule.AcceptedFormats.Contains("email");
        bool isGivenSpellingAccepted = rule.AcceptedFormats.Contains("EMAIL");

        Assert.IsFalse(isLowerCaseSpellingAccepted);
        Assert.IsTrue(isGivenSpellingAccepted);
        Assert.AreEqual(IdJagValidationFailureReason.UnsupportedSubjectIdentifierFormat, result.FailureReason);
    }


    /// <summary>
    /// A presence value outside <see cref="IdJagSubjectIdentifierPresence"/> is read as
    /// <see cref="IdJagSubjectIdentifierPresence.Required"/>, so a grant without a <c>sub_id</c> claim is
    /// refused as missing it. The reading is this library's; no clause of a specification states it.
    /// </summary>
    [TestMethod]
    public async Task APresenceOutsideTheEnumerationIsReadAsRequired()
    {
        IdJagSubjectIdentifierRule rule = new() { Presence = (IdJagSubjectIdentifierPresence)99 };

        IdJagAssertionValidationResult result = await ValidateAsync(ValidPayload(), rule).ConfigureAwait(false);

        Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierRequired, result.FailureReason);
    }


    /// <summary>
    /// An outcome outside <see cref="ComparisonOutcome"/> that the association answers is decided as
    /// <see cref="ComparisonDecision.IndeterminateDeny"/>, and the grant is refused as undetermined, whatever
    /// the presence of the claim. The decision is this library's; no clause of a specification states it.
    /// </summary>
    [TestMethod]
    public async Task AnOutcomeOutsideTheEnumerationDecidesAsUndetermined()
    {
        IdJagSubjectIdentifierRule rule = new()
        {
            Relation = ComparisonRelation.Equal,
            Association = static (candidate, reference, relation, cancellationToken) =>
                ValueTask.FromResult((ComparisonOutcome)99)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.SubId] = SubjectIdentifier.Email("alice@example.com").ToWireObject();

        IdJagAssertionValidationResult result = await ValidateAsync(payload, rule).ConfigureAwait(false);

        Assert.AreEqual(IdJagValidationFailureReason.SubjectIdentifierUndetermined, result.FailureReason);
        Assert.IsNotNull(result.SubjectIdentifierComparison);
        Assert.AreEqual(ComparisonDecision.IndeterminateDeny, result.SubjectIdentifierComparison.Decision);
    }


    /// <summary>
    /// The association is put to once when it decides a claim: an <c>email</c> claim of another namespace under
    /// an equality rule is held by the association, which is called exactly once, and the record names the
    /// application's rule as its basis. The call count is this library's rule; no clause of a specification
    /// states it.
    /// </summary>
    [TestMethod]
    public async Task TheAssociationIsAskedOnceWhenItDecides()
    {
        int associationCalls = 0;
        IdJagSubjectIdentifierRule rule = new()
        {
            Relation = ComparisonRelation.Equal,
            Association = (candidate, reference, relation, cancellationToken) =>
            {
                associationCalls++;

                return ValueTask.FromResult(ComparisonOutcome.Holds);
            }
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.SubId] = SubjectIdentifier.Email("alice@example.com").ToWireObject();

        IdJagAssertionValidationResult result = await ValidateAsync(payload, rule).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNotNull(result.SubjectIdentifierComparison);
        Assert.AreEqual(ComparisonOutcome.Holds, result.SubjectIdentifierComparison.Outcome);
        Assert.AreEqual(ComparisonBasis.ApplicationRule, result.SubjectIdentifierComparison.Basis);
        Assert.AreEqual(ComparisonDecision.Permit, result.SubjectIdentifierComparison.Decision);
        Assert.AreEqual(1, associationCalls);
    }


    /// <summary>
    /// An exception the association throws reaches the caller of the validation unchanged, as the same
    /// exception instance: it is a defect of the application's delegate, not a value the validation turns into
    /// a refusal. The rule is this library's; no clause of a specification states it.
    /// </summary>
    [TestMethod]
    public async Task AnExceptionOfTheAssociationReachesTheCaller()
    {
        InvalidOperationException fault = new("The application's association failed.");
        IdJagSubjectIdentifierRule rule = new()
        {
            Relation = ComparisonRelation.Equal,
            Association = (candidate, reference, relation, cancellationToken) => throw fault
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.SubId] = SubjectIdentifier.Email("alice@example.com").ToWireObject();

        InvalidOperationException reached = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => _ = await ValidateAsync(payload, rule).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreSame(fault, reached);
    }
}
