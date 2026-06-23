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
}
