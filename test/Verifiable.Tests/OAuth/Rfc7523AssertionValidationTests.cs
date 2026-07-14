using Verifiable.JCose;
using Verifiable.OAuth.JwtBearer;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit coverage for <see cref="Rfc7523AssertionValidation"/> — the reusable
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see> claim-rule checker
/// generic (non-ID-JAG) jwt-bearer deployments consume directly. <see cref="IdJagAssertionValidation"/>
/// consumes the SAME implementation for its own iss/sub/aud/exp/nbf/iat checks
/// (<see cref="IdJagAssertionValidationTests"/> is the regression proof that extraction did not change
/// its byte-identical behavior); this file pins the standalone entry point's own contract.
/// </summary>
[TestClass]
internal sealed class Rfc7523AssertionValidationTests
{
    private const string Issuer = "https://idp.example.com/";
    private const string Audience = "https://rs.example.com/";
    private const string Subject = "U019488227";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_311_280_970);
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(60);


    private static JwtPayload ValidPayload() =>
        new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = Issuer,
            [WellKnownJwtClaimNames.Sub] = Subject,
            [WellKnownJwtClaimNames.Aud] = Audience,
            [WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds()
        };


    private static Rfc7523AssertionValidationResult Validate(JwtPayload payload) =>
        Rfc7523AssertionValidation.Validate(payload, Audience, Now, Skew);


    [TestMethod]
    public void ValidAssertionPassesAndSurfacesClaims()
    {
        Rfc7523AssertionValidationResult result = Validate(ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.FailureReason);
        Assert.AreEqual(Issuer, result.Issuer);
        Assert.AreEqual(Subject, result.Subject);
        Assert.AreEqual(Audience, result.Audience);
        Assert.IsNotNull(result.IssuedAt);
        Assert.IsNotNull(result.Expiration);
    }


    /// <summary>§3 item 1: <c>iss</c> MUST be present.</summary>
    [TestMethod]
    public void MissingIssuerIsMissingIssuer()
    {
        JwtPayload payload = ValidPayload();
        payload.Remove(WellKnownJwtClaimNames.Iss);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.MissingIssuer, result.FailureReason);
    }


    /// <summary>§3 item 2: <c>sub</c> MUST be present.</summary>
    [TestMethod]
    public void MissingSubjectIsMissingSubject()
    {
        JwtPayload payload = ValidPayload();
        payload.Remove(WellKnownJwtClaimNames.Sub);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.MissingSubject, result.FailureReason);
    }


    /// <summary>§3 item 3: <c>aud</c> MUST be present.</summary>
    [TestMethod]
    public void MissingAudienceIsMissingAudience()
    {
        JwtPayload payload = ValidPayload();
        payload.Remove(WellKnownJwtClaimNames.Aud);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.MissingAudience, result.FailureReason);
    }


    /// <summary>§3 item 3: <c>aud</c> MUST name the caller's own identity — a different string is rejected.</summary>
    [TestMethod]
    public void AudienceStringMismatchIsAudienceMismatch()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = "https://other.example.com/";

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    /// <summary>A single-element array naming the caller's identity is an accepted <c>aud</c> shape.</summary>
    [TestMethod]
    public void AudienceSingleElementArrayIsAccepted()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new object[] { Audience };

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreEqual(Audience, result.Audience);
    }


    /// <summary>
    /// The anti-audience-injection hardening this checker inherited from
    /// <see cref="IdJagAssertionValidation"/>'s original implementation: a multi-element array is
    /// rejected even when one element matches, so an assertion crafted to also be valid at another
    /// audience can never be replayed here.
    /// </summary>
    [TestMethod]
    public void AudienceMultiElementArrayIsRejectedEvenWhenOneMatches()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new object[] { Audience, "https://evil.example.com/" };

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    /// <summary>§3 item 4: <c>exp</c> MUST be present.</summary>
    [TestMethod]
    public void MissingExpirationIsMissingExpiration()
    {
        JwtPayload payload = ValidPayload();
        payload.Remove(WellKnownJwtClaimNames.Exp);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.MissingExpiration, result.FailureReason);
    }


    /// <summary>§3 item 4: the AS MUST reject an expired assertion (subject to clock skew).</summary>
    [TestMethod]
    public void ExpiredAssertionIsExpired()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-5).ToUnixTimeSeconds();

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.Expired, result.FailureReason);
    }


    /// <summary>§3 item 5: a future <c>nbf</c> (beyond skew) makes the assertion not yet valid.</summary>
    [TestMethod]
    public void FutureNotBeforeIsNotYetValid()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = Now.AddMinutes(2).ToUnixTimeSeconds();

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.NotYetValid, result.FailureReason);
    }


    /// <summary><c>exp</c> at or before <c>iat</c> is an internally inconsistent, non-positive lifetime — rejected independent of the clock.</summary>
    [TestMethod]
    public void ExpiryAtOrBeforeIssuedAtIsInconsistent()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-1).ToUnixTimeSeconds();

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.InconsistentTemporalClaims, result.FailureReason);
    }


    /// <summary>§3 item 6: <c>iat</c> is OPTIONAL — its absence does not fail validation.</summary>
    [TestMethod]
    public void AbsentIssuedAtStillValidates()
    {
        JwtPayload payload = ValidPayload();
        payload.Remove(WellKnownJwtClaimNames.Iat);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.IssuedAt);
    }
}
