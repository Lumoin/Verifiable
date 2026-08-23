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

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_311_280_970);
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(60);


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
        payload.Remove(WellKnownJwtClaimNames.Iss);

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
        payload.Remove(WellKnownJwtClaimNames.Aud);

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
        payload.Remove(WellKnownJwtClaimNames.ClientId);

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
        payload.Remove(WellKnownJwtClaimNames.Sub);

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.AreEqual(IdJagValidationFailureReason.MissingSubject, result.FailureReason);
    }


    [TestMethod]
    public void MissingExpirationIsMissingExpiration()
    {
        JwtPayload payload = ValidPayload();
        payload.Remove(WellKnownJwtClaimNames.Exp);

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


    [TestMethod]
    public void NonArrayAuthorizationDetailsSurfacesNull()
    {
        JwtPayload payload = ValidPayload();
        payload["authorization_details"] = "not-an-array";

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.AuthorizationDetails);
    }


    [TestMethod]
    public void ResourceArrayDropsNonStringElements()
    {
        JwtPayload payload = ValidPayload();
        payload["resource"] = new object[] { "https://api.chat.example/files", 123L };

        IdJagAssertionValidationResult result = Validate(ValidHeader(), payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.HasCount(1, result.Resource);
        Assert.AreEqual("https://api.chat.example/files", result.Resource[0]);
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
        Assert.AreEqual(CurrentActorSubject, (string)result.Act![WellKnownJwtClaimNames.Sub]);
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
        Assert.AreEqual(CurrentActorSubject, (string)result.MayAct![WellKnownJwtClaimNames.Sub]);
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
}
