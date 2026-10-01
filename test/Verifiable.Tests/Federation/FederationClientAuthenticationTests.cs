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
    /// An <c>exp</c>, <c>iat</c> or <c>nbf</c> whose number names no instant a <see cref="DateTimeOffset"/> can
    /// hold refuses the client authentication JWT as a malformed time claim, and the check answers a result
    /// rather than throwing: the integer 1000000000000000, as the library's decoder hands it (a 64-bit integer),
    /// and a number beyond a 64-bit integer, which the decoder hands as a <see cref="decimal"/>. Each is a
    /// NumericDate, and refusing it is this library's fail-closed reading: no instant the checks compare can hold
    /// it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see>: "NumericDate A JSON
    /// numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
    /// date/time, ignoring leap seconds."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 4, for the
    /// <c>exp</c>: "Note that the authorization server may reject JWTs with an "exp" claim value that is
    /// unreasonably far in the future."
    /// </summary>
    /// <param name="claimName">The time claim the value is set on.</param>
    /// <param name="caseName">The value: <c>tenToTheFifteen</c> or <c>beyondALong</c>.</param>
    [TestMethod]
    [DataRow("exp", "tenToTheFifteen", DisplayName = "an exp of 1e15")]
    [DataRow("iat", "tenToTheFifteen", DisplayName = "an iat of 1e15")]
    [DataRow("nbf", "tenToTheFifteen", DisplayName = "an nbf of 1e15")]
    [DataRow("exp", "beyondALong", DisplayName = "an exp beyond a 64-bit integer")]
    public void ATimeClaimNoInstantCanHoldIsRejected(string claimName, string caseName)
    {
        object value = caseName switch
        {
            "tenToTheFifteen" => (object)1_000_000_000_000_000L,
            "beyondALong" => 100_000_000_000_000_000_000m,
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[claimName] = value;

        FederationClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
        Assert.Contains($"{claimName} claim", result.FailureReason!);
        Assert.Contains("malformed", result.FailureReason!);
    }


    /// <summary>
    /// A fractional <c>exp</c> keeps its fraction, and the fraction decides under the clock: an <c>exp</c> half a
    /// second past the edge of the clock skew is not expired, as a <see cref="decimal"/> (the library's decoder)
    /// or a <see cref="double"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see>: "This is equivalent
    /// to the IEEE Std 1003.1, 2013 Edition [POSIX.1] definition "Seconds Since the Epoch", in which each day is
    /// accounted for by exactly 86400 seconds, other than that non-integer values can be represented."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 4: "The
    /// authorization server MUST reject any JWT with an expiration time that has passed, subject to allowable
    /// clock skew between systems."
    /// </summary>
    /// <param name="caseName">The shape of the fractional value: <c>decimal</c> or <c>double</c>.</param>
    [TestMethod]
    [DataRow("decimal", DisplayName = "an exp half a second inside the skew, as a decimal")]
    [DataRow("double", DisplayName = "an exp half a second inside the skew, as a double")]
    public void AFractionalExpirationIsKeptAndDecides(string caseName)
    {
        long edgeSeconds = Now.Add(-Skew).ToUnixTimeSeconds();
        object expiration = caseName switch
        {
            "decimal" => edgeSeconds + 0.5m,
            "double" => edgeSeconds + 0.5d,
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Exp] = expiration;

        FederationClientAuthenticationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(DateTimeOffset.FromUnixTimeSeconds(edgeSeconds).AddMilliseconds(500), result.Expiration);
    }


    /// <summary>
    /// An <c>exp</c> at the last instant a <see cref="DateTimeOffset"/> holds is not expired under a skew of 60
    /// seconds, and the check answers a result rather than throwing: the last whole second, 253402300799, as a
    /// 64-bit integer, and its last tick, 253402300799.9999999, as a <see cref="decimal"/>. Accepting an expiry
    /// that far ahead is this library's choice.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 4: "The
    /// authorization server MUST reject any JWT with an expiration time that has passed, subject to allowable
    /// clock skew between systems. Note that the authorization server may reject JWTs with an "exp" claim value
    /// that is unreasonably far in the future."
    /// </summary>
    /// <param name="caseName">The value: <c>lastWholeSecond</c> or <c>lastTick</c>.</param>
    [TestMethod]
    [DataRow("lastWholeSecond", DisplayName = "an exp of 253402300799")]
    [DataRow("lastTick", DisplayName = "an exp of 253402300799.9999999")]
    public void AnExpirationAtTheLastRepresentableInstantIsNotExpired(string caseName)
    {
        (object expiration, DateTimeOffset expectedExpiration) = caseName switch
        {
            "lastWholeSecond" => ((object)253_402_300_799L, DateTimeOffset.FromUnixTimeSeconds(253_402_300_799)),
            "lastTick" => (253_402_300_799.9999999m, DateTimeOffset.MaxValue),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Exp] = expiration;

        FederationClientAuthenticationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(expectedExpiration, result.Expiration);
    }


    /// <summary>
    /// An <c>exp</c>, <c>iat</c> or <c>nbf</c> that is a JSON string holding digits refuses the client
    /// authentication JWT as a malformed time claim, whatever instant the digits would name as a number.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</see>, of the
    /// <c>exp</c>, <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">Section 4.1.5</see>, of the
    /// <c>nbf</c>, and <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">Section 4.1.6</see>, of
    /// the <c>iat</c>: "Its value MUST be a number containing a NumericDate value."
    /// </summary>
    /// <param name="claimName">The time claim the string is set on.</param>
    /// <param name="digits">The string, digits that as a number would name an instant the checks accept.</param>
    [TestMethod]
    [DataRow("exp", "1700000000", DisplayName = "an exp of the string 1700000000")]
    [DataRow("iat", "1699999940", DisplayName = "an iat of the string 1699999940")]
    [DataRow("nbf", "1699999940", DisplayName = "an nbf of the string 1699999940")]
    public void ATimeClaimThatIsAJsonStringIsRejected(string claimName, string digits)
    {
        JwtPayload payload = ValidPayload();
        payload[claimName] = digits;

        FederationClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid, $"The string {digits} was read as the {claimName} claim.");
        Assert.Contains($"{claimName} claim", result.FailureReason!);
        Assert.Contains("malformed", result.FailureReason!);
    }


    /// <summary>
    /// The edge of the skew decides the expiry to the tick: an <c>exp</c> exactly one skew before the clock
    /// refuses the client authentication JWT as expired, and one a tick later (a fraction of 0.0000001 second) is
    /// not expired, its fraction kept.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 4: "The
    /// authorization server MUST reject any JWT with an expiration time that has passed, subject to allowable
    /// clock skew between systems."
    /// </summary>
    /// <param name="caseName">The <c>exp</c>: <c>atTheEdge</c> or <c>oneTickLater</c>.</param>
    [TestMethod]
    [DataRow("atTheEdge", DisplayName = "an exp exactly one skew before the clock")]
    [DataRow("oneTickLater", DisplayName = "an exp one tick later than that")]
    public void TheEdgeOfTheSkewDecidesTheExpiryToTheTick(string caseName)
    {
        long edgeSeconds = Now.Add(-Skew).ToUnixTimeSeconds();
        (object expiration, string? expectedFailure, DateTimeOffset? expectedExpiration) = caseName switch
        {
            "atTheEdge" => ((object)edgeSeconds, "The client authentication JWT has expired.", (DateTimeOffset?)null),
            "oneTickLater" => (edgeSeconds + 0.0000001m, null, DateTimeOffset.FromUnixTimeSeconds(edgeSeconds).AddTicks(1)),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Exp] = expiration;

        FederationClientAuthenticationResult result = Validate(payload);

        Assert.AreEqual(expectedFailure, result.FailureReason);
        Assert.AreEqual(expectedExpiration, result.Expiration);
    }


    /// <summary>
    /// The edge of the skew decides the not-before to the tick: an <c>nbf</c> exactly one skew after the clock is
    /// in force, and one a tick later (a fraction of 0.0000001 second) refuses the client authentication JWT as
    /// not yet valid.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 5: "The JWT MAY
    /// contain an "nbf" (not before) claim that identifies the time before which the token MUST NOT be accepted
    /// for processing."
    /// </summary>
    /// <param name="caseName">The <c>nbf</c>: <c>atTheEdge</c> or <c>oneTickLater</c>.</param>
    [TestMethod]
    [DataRow("atTheEdge", DisplayName = "an nbf exactly one skew after the clock")]
    [DataRow("oneTickLater", DisplayName = "an nbf one tick later than that")]
    public void TheEdgeOfTheSkewDecidesTheNotBeforeToTheTick(string caseName)
    {
        long edgeSeconds = Now.Add(Skew).ToUnixTimeSeconds();
        (object notBefore, string? expectedFailure) = caseName switch
        {
            "atTheEdge" => ((object)edgeSeconds, (string?)null),
            "oneTickLater" => (edgeSeconds + 0.0000001m, "The client authentication JWT is not yet valid (nbf is in the future beyond the skew tolerance)."),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = notBefore;

        FederationClientAuthenticationResult result = Validate(payload);

        Assert.AreEqual(expectedFailure, result.FailureReason);
    }
}
