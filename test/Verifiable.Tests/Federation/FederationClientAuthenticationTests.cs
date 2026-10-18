using System.Globalization;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Unit coverage for <see cref="FederationClientAuthentication"/> — the §8.8
/// <c>private_key_jwt</c> claim rules a federation endpoint applies to a
/// decoded, signature-verified client-authentication JWT. Each test pins one
/// normative rule.
/// </summary>
[TestClass]
internal sealed class FederationClientAuthenticationTests
{
    private const string EndpointEntityId = "https://op.example.com";
    private const string RequesterEntityId = "https://rp.example.com";

    private static DateTimeOffset Now { get; } = DateTimeOffset.FromUnixTimeSeconds(1_700_000_000);
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);

    private static EntityIdentifier Endpoint { get; } = new(EndpointEntityId);
    private static EntityIdentifier Requester { get; } = new(RequesterEntityId);


    private static JwtPayload ValidPayload() =>
        new(capacity: 5)
        {
            [WellKnownJwtClaimNames.Iss] = RequesterEntityId,
            [WellKnownJwtClaimNames.Sub] = RequesterEntityId,
            [WellKnownJwtClaimNames.Aud] = EndpointEntityId,
            [WellKnownJwtClaimNames.Jti] = "f81b64a33f20116179",
            [WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds(),
        };


    private static FederationClientAuthenticationResult Validate(JwtPayload payload) =>
        FederationClientAuthentication.Validate(payload, Endpoint, Requester, Now, Skew);


    [TestMethod]
    public void ValidAssertionPassesAndSurfacesClaims()
    {
        FederationClientAuthenticationResult result = Validate(ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(RequesterEntityId, result.ClientId);
        Assert.AreEqual("f81b64a33f20116179", result.Jti);
    }


    [TestMethod]
    public void AudienceThatIsNotTheEndpointIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = "https://attacker.example.com";

        Assert.IsFalse(Validate(payload).IsValid,
            "§8.8: aud must be the endpoint's Entity Identifier.");
    }


    [TestMethod]
    public void MultiValuedAudienceContainingTheEndpointIsRejected()
    {
        //§8.8: the endpoint MUST NOT accept audience values other than its own
        //Entity Identifier — a multi-element array (even one that contains the
        //endpoint) is an audience-injection attempt.
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new List<object> { EndpointEntityId, "https://attacker.example.com" };

        Assert.IsFalse(Validate(payload).IsValid,
            "A multi-valued aud must be rejected even when it contains the endpoint.");
    }


    [TestMethod]
    public void IssuerThatIsNotTheRequesterIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iss] = "https://impostor.example.com";

        Assert.IsFalse(Validate(payload).IsValid,
            "private_key_jwt: iss must be the requester's Entity Identifier.");
    }


    [TestMethod]
    public void SubjectThatIsNotTheRequesterIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Sub] = "https://impostor.example.com";

        Assert.IsFalse(Validate(payload).IsValid,
            "private_key_jwt: sub must be the requester's Entity Identifier.");
    }


    [TestMethod]
    public void MissingJtiIsRejected()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Jti);

        Assert.IsFalse(Validate(payload).IsValid, "jti is required for replay defense.");
    }


    [TestMethod]
    public void MissingExpirationIsRejected()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Exp);

        Assert.IsFalse(Validate(payload).IsValid, "exp is required.");
    }


    [TestMethod]
    public void ExpiredAssertionIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-5).ToUnixTimeSeconds();

        Assert.IsFalse(Validate(payload).IsValid, "An expired assertion must be rejected.");
    }

    /// <summary>
    /// RFC 7519 Section 2: the JWT's NumericDates may carry a fraction, each judged to the tick under the clock-skew tolerance:
    /// an <c>exp</c> a quarter of a second after the present less the tolerance is still live and surfaced as written, where a
    /// fraction was once refused as malformed; an <c>nbf</c> a quarter of a second past the present plus the tolerance is not yet
    /// valid; and a string of digits is no NumericDate, where it was once read as the count it spells.
    /// </summary>
    [TestMethod]
    public void FractionalDatesAreJudgedToTheTickAndAStringIsNoNumericDate()
    {
        var second = Now.ToUnixTimeSeconds();
        var toleranceSeconds = (long)Skew.TotalSeconds;

        var live = ValidPayload();
        live[WellKnownJwtClaimNames.Exp] = second - toleranceSeconds + 0.25m;

        var result = Validate(live);

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(Now.AddSeconds(-toleranceSeconds).AddMilliseconds(250), result.Expiration, "The exp is the instant written.");

        var notYetValid = ValidPayload();
        notYetValid[WellKnownJwtClaimNames.Nbf] = second + toleranceSeconds + 0.25m;

        Assert.IsFalse(Validate(notYetValid).IsValid, "An nbf a quarter of a second past the tolerance is not yet valid.");

        var spelled = ValidPayload();
        spelled[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);

        Assert.IsFalse(Validate(spelled).IsValid, "A string of digits is no NumericDate.");
    }


    /// <summary>
    /// RFC 7519 Section 4.1.4 under the clock-skew tolerance: an <c>exp</c> at the clock's last tick is judged without the
    /// tolerance carrying the instant past the clock, so the assertion is live, where adding the tolerance to the expiry threw;
    /// and the instant at which the present lies exactly at <c>exp</c> extended by the tolerance has expired, the tick before it
    /// live.
    /// </summary>
    [TestMethod]
    public void AnExpiryAtTheClocksLastTickOverflowsNoComparisonAndTheBoundIsExclusive()
    {
        var atTheClocksEnd = ValidPayload();
        atTheClocksEnd[WellKnownJwtClaimNames.Exp] = 253_402_300_799.9999999m;

        var live = Validate(atTheClocksEnd);

        Assert.IsTrue(live.IsValid, live.FailureReason);

        var atTheBound = ValidPayload();
        atTheBound[WellKnownJwtClaimNames.Exp] = Now.AddSeconds(-Skew.TotalSeconds).ToUnixTimeSeconds();

        Assert.IsFalse(Validate(atTheBound).IsValid, "An exp the tolerance before the present has expired.");

        var aTickInside = ValidPayload();
        aTickInside[WellKnownJwtClaimNames.Exp] = Now.AddSeconds(-Skew.TotalSeconds).ToUnixTimeSeconds() + 0.0000001m;

        Assert.IsTrue(Validate(aTickInside).IsValid, "An exp a tick after that is live.");
    }
}
