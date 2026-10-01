using Verifiable.JCose;
using Verifiable.OAuth.JwtBearer;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Unit coverage for <see cref="Rfc7523AssertionValidation"/> — the reusable
/// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 §3</see> claim-rule checker
/// generic (non-ID-JAG) jwt-bearer deployments consume directly. <see cref="Verifiable.OAuth.IdJag.IdJagAssertionValidation"/>
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

    private static DateTimeOffset Now { get; } = DateTimeOffset.FromUnixTimeSeconds(1_311_280_970);
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);


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
        _ = payload.Remove(WellKnownJwtClaimNames.Iss);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.MissingIssuer, result.FailureReason);
    }


    /// <summary>§3 item 2: <c>sub</c> MUST be present.</summary>
    [TestMethod]
    public void MissingSubjectIsMissingSubject()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Sub);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.MissingSubject, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 2: "The
    /// JWT MUST contain a "sub" (subject) claim identifying the principal that is the subject of the JWT."
    /// A <c>sub</c> of white space only (a space, a tab, a no-break space) identifies no principal. That
    /// reading is this library's, the one the ID-JAG validator applies to the same claim, and
    /// <see cref="Rfc7523AssertionValidation.Validate"/> refuses such an assertion as
    /// <see cref="Rfc7523AssertionValidationFailureReason.MissingSubject"/>.
    /// </summary>
    /// <param name="codePoint">The code point the <c>sub</c> value consists of, passed as a number so the source carries no raw white space character.</param>
    [TestMethod]
    [DataRow(0x0020)]
    [DataRow(0x0009)]
    [DataRow(0x00A0)]
    public void ASubjectOfWhiteSpaceOnlyIsNoSubject(int codePoint)
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Sub] = char.ConvertFromUtf32(codePoint);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.MissingSubject, result.FailureReason);
    }


    /// <summary>§3 item 3: <c>aud</c> MUST be present.</summary>
    [TestMethod]
    public void MissingAudienceIsMissingAudience()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Aud);

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
    /// <see cref="Verifiable.OAuth.IdJag.IdJagAssertionValidation"/>'s original implementation: a multi-element array is
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
        _ = payload.Remove(WellKnownJwtClaimNames.Exp);

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
        _ = payload.Remove(WellKnownJwtClaimNames.Iat);

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.IsNull(result.IssuedAt);
    }


    /// <summary>
    /// An <c>exp</c>, <c>iat</c> or <c>nbf</c> whose number names no instant a <see cref="DateTimeOffset"/> can hold
    /// is a NumericDate this server cannot represent, refused as
    /// <see cref="Rfc7523AssertionValidationFailureReason.InconsistentTemporalClaims"/> with a description that
    /// says so, and the read answers a failed result rather than throwing: the integer 1000000000000000, as the
    /// library's decoder hands it (a 64-bit integer), and a number beyond a 64-bit integer, which the decoder hands
    /// as a <see cref="decimal"/>. Refusing such a value is this library's fail-closed reading: no instant the
    /// checks compare can hold it.
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
    public void ANumericDateNoInstantCanHoldIsInconsistent(string claimName, string caseName)
    {
        object value = caseName switch
        {
            "tenToTheFifteen" => (object)1_000_000_000_000_000L,
            "beyondALong" => 100_000_000_000_000_000_000m,
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[claimName] = value;

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.InconsistentTemporalClaims, result.FailureReason);
        Assert.AreEqual($"The assertion {claimName} claim is a NumericDate this server cannot represent.", result.FailureDescription);
    }


    /// <summary>
    /// An <c>exp</c>, <c>iat</c> or <c>nbf</c> that is a JSON string holding digits is not a time claim and is
    /// refused as <see cref="Rfc7523AssertionValidationFailureReason.InconsistentTemporalClaims"/>, with the
    /// description of a time claim that is not a numeric timestamp, whatever instant the digits would name.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</see>, of the
    /// <c>exp</c>, <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">Section 4.1.5</see>, of the
    /// <c>nbf</c>, and <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">Section 4.1.6</see>, of
    /// the <c>iat</c>: "Its value MUST be a number containing a NumericDate value."
    /// </summary>
    /// <param name="claimName">The time claim the string is set on.</param>
    /// <param name="digits">The string, digits that as a number would name an instant the checks accept.</param>
    [TestMethod]
    [DataRow("exp", "1700000000", DisplayName = "an exp of the string 1700000000")]
    [DataRow("iat", "1311280910", DisplayName = "an iat of the string 1311280910")]
    [DataRow("nbf", "1311280910", DisplayName = "an nbf of the string 1311280910")]
    public void ATimeClaimThatIsAJsonStringIsInconsistent(string claimName, string digits)
    {
        JwtPayload payload = ValidPayload();
        payload[claimName] = digits;

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(Rfc7523AssertionValidationFailureReason.InconsistentTemporalClaims, result.FailureReason);
        Assert.AreEqual($"The assertion {claimName} claim is not a numeric timestamp.", result.FailureDescription);
    }


    /// <summary>
    /// The edge of the skew decides the expiry to the tick: an <c>exp</c> exactly one skew before the clock is
    /// expired, and one an instant of a tick later (a fraction of 0.0000001 second) is not, its fraction kept.
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
        (object expiration, Rfc7523AssertionValidationFailureReason? expectedReason, DateTimeOffset? expectedExpiration) = caseName switch
        {
            "atTheEdge" => ((object)edgeSeconds, (Rfc7523AssertionValidationFailureReason?)Rfc7523AssertionValidationFailureReason.Expired, (DateTimeOffset?)null),
            "oneTickLater" => (edgeSeconds + 0.0000001m, null, DateTimeOffset.FromUnixTimeSeconds(edgeSeconds).AddTicks(1)),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = expiration;

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(expectedReason, result.FailureReason, result.FailureDescription);
        Assert.AreEqual(expectedExpiration, result.Expiration);
    }


    /// <summary>
    /// The edge of the skew decides the not-before to the tick: an <c>nbf</c> exactly one skew after the clock is
    /// in force, and one a tick later (a fraction of 0.0000001 second) is not yet valid.
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
        (object notBefore, Rfc7523AssertionValidationFailureReason? expectedReason) = caseName switch
        {
            "atTheEdge" => ((object)edgeSeconds, (Rfc7523AssertionValidationFailureReason?)null),
            "oneTickLater" => (edgeSeconds + 0.0000001m, Rfc7523AssertionValidationFailureReason.NotYetValid),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = notBefore;

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.AreEqual(expectedReason, result.FailureReason, result.FailureDescription);
    }


    /// <summary>
    /// A fractional NumericDate keeps its fraction, and the fraction decides: an <c>exp</c> half a second past
    /// the clock skew's edge is not expired, as a <see cref="decimal"/> (the library's decoder) or a
    /// <see cref="double"/>; and an <c>iat</c> and an <c>exp</c> a fraction apart within one whole second keep a
    /// positive lifetime.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see>: "This is equivalent
    /// to the IEEE Std 1003.1, 2013 Edition [POSIX.1] definition "Seconds Since the Epoch", in which each day is
    /// accounted for by exactly 86400 seconds, other than that non-integer values can be represented."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 4: "The
    /// authorization server MUST reject any JWT with an expiration time that has passed, subject to allowable
    /// clock skew between systems."
    /// </summary>
    /// <param name="caseName">The fractional claims: <c>decimalExpiration</c>, <c>doubleExpiration</c> or <c>oneSecond</c>.</param>
    [TestMethod]
    [DataRow("decimalExpiration", DisplayName = "an exp half a second inside the skew, as a decimal")]
    [DataRow("doubleExpiration", DisplayName = "an exp half a second inside the skew, as a double")]
    [DataRow("oneSecond", DisplayName = "an iat and an exp within one whole second")]
    public void AFractionalNumericDateKeepsItsFraction(string caseName)
    {
        long edgeSeconds = Now.Add(-Skew).ToUnixTimeSeconds();
        long laterSeconds = Now.AddMinutes(1).ToUnixTimeSeconds();
        (object IssuedAt, object Expiration, DateTimeOffset ExpectedExpiration) fractionCase = caseName switch
        {
            "decimalExpiration" => (
                Now.AddMinutes(-10).ToUnixTimeSeconds(),
                edgeSeconds + 0.5m,
                DateTimeOffset.FromUnixTimeSeconds(edgeSeconds).AddMilliseconds(500)),
            "doubleExpiration" => (
                Now.AddMinutes(-10).ToUnixTimeSeconds(),
                edgeSeconds + 0.5d,
                DateTimeOffset.FromUnixTimeSeconds(edgeSeconds).AddMilliseconds(500)),
            "oneSecond" => (
                laterSeconds + 0.1m,
                laterSeconds + 0.9m,
                DateTimeOffset.FromUnixTimeSeconds(laterSeconds).AddMilliseconds(900)),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = fractionCase.IssuedAt;
        payload[WellKnownJwtClaimNames.Exp] = fractionCase.Expiration;

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreEqual(fractionCase.ExpectedExpiration, result.Expiration);
    }


    /// <summary>
    /// An <c>exp</c> at the last instant a <see cref="DateTimeOffset"/> holds is not expired under a skew of 60
    /// seconds, and the check answers a result rather than throwing: the last whole second, 253402300799, as the
    /// library's decoder hands it (a 64-bit integer), and its last tick, 253402300799.9999999, as a
    /// <see cref="decimal"/>. The comparison of the expiry with the clock and its skew leaves no sum outside the
    /// representable instants. Accepting an expiry that far ahead is this library's choice.
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

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
        Assert.AreEqual(expectedExpiration, result.Expiration);
    }


    /// <summary>
    /// An <c>nbf</c> at the first instant a <see cref="DateTimeOffset"/> holds, -62135596800, is in force under a
    /// skew of 60 seconds, and the check answers a result rather than throwing.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see> item 5: "The JWT MAY
    /// contain an "nbf" (not before) claim that identifies the time before which the token MUST NOT be accepted
    /// for processing."
    /// </summary>
    [TestMethod]
    public void ANotBeforeAtTheFirstRepresentableInstantIsInForce()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = -62_135_596_800L;

        Rfc7523AssertionValidationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureDescription);
    }
}
