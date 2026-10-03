using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Claim-rule matrix for <see cref="PrivateKeyJwtClientAuthentication"/> — the RFC 7523 §2.2/§3/§3.2
/// <c>private_key_jwt</c> client-authentication seam draft-ietf-oauth-client-id-metadata-document-02
/// §8.2 (CIMD-047/048/049/050) requires. Part A exercises the pure
/// <see cref="PrivateKeyJwtClientAuthentication.Validate"/> claim rules directly, mirroring
/// <c>Rfc7523AssertionValidationTests</c>'s style. Part B exercises the full
/// <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
/// pipeline — parse, key resolution from a JWKS, real signature verification, then the claim rules —
/// against a project-crypto-generated P-256 key pair via <see cref="TestKeyMaterialProvider"/> and
/// <see cref="ClientAssertionSigning"/>, never <c>System.Security.Cryptography</c> directly.
/// </summary>
[TestClass]
internal sealed class PrivateKeyJwtClientAuthenticationTests
{
    private const string ClientId = "https://client.example/app";
    private const string Issuer = "https://issuer.test/tenant-a";
    private const string SigningKeyId = "test-client-key-1";

    private static DateTimeOffset Now { get; } = DateTimeOffset.FromUnixTimeSeconds(1_311_280_970);
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);

    public TestContext TestContext { get; set; } = null!;


    //Part A — the pure claim-rule checker. No crypto, no host: JwtPayload is constructed directly,
    //exactly as an already-signature-verified assertion payload would arrive.

    private static JwtPayload ValidPayload() =>
        new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = ClientId,
            [WellKnownJwtClaimNames.Sub] = ClientId,
            [WellKnownJwtClaimNames.Aud] = Issuer,
            [WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-1).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = Now.AddMinutes(5).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = "assertion-jti-1"
        };


    private static PrivateKeyJwtClientAuthenticationResult Validate(JwtPayload payload) =>
        PrivateKeyJwtClientAuthentication.Validate(payload, ClientId, [Issuer], Now, Skew);


    [TestMethod]
    public void ValidAssertionPassesAndSurfacesClaims()
    {
        PrivateKeyJwtClientAuthenticationResult result = Validate(ValidPayload());

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(ClientId, result.ClientId);
        Assert.AreEqual("assertion-jti-1", result.Jti);
        Assert.IsNotNull(result.Expiration);
    }


    /// <summary>RFC 7523 §3 item 1: a wrong <c>iss</c> (not the client_id) is rejected.</summary>
    [TestMethod]
    public void WrongIssuerIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iss] = "https://impostor.example/app";

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
        Assert.IsNull(result.ClientId);
    }


    /// <summary>RFC 7523 §3 item 2.B: a wrong <c>sub</c> (not the client_id) is rejected.</summary>
    [TestMethod]
    public void WrongSubjectIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Sub] = "https://impostor.example/app";

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>RFC 7523 §3 item 3: an <c>aud</c> naming a foreign authorization server is rejected.</summary>
    [TestMethod]
    public void ForeignAudienceIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = "https://other-as.example/";

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// An <c>aud</c> array carrying the accepted issuer ALONGSIDE a foreign value is rejected outright
    /// — every element must be an accepted AS identity, not merely one of them.
    /// </summary>
    [TestMethod]
    public void ForeignAudienceMixedIntoArrayIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = new object[] { Issuer, "https://evil.example/" };

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>Missing <c>aud</c> is rejected (RFC 7523 §3 item 3).</summary>
    [TestMethod]
    public void MissingAudienceIsRejected()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Aud);

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// RFC 7523 §3 item 3: "The token endpoint URL of the authorization server MAY be used as a
    /// value for an &quot;aud&quot; element" — a caller that additionally accepts the token endpoint URL sees an
    /// assertion audienced to it validate.
    /// </summary>
    [TestMethod]
    public void TokenEndpointUrlIsAnAcceptedAlternateAudience()
    {
        const string TokenEndpoint = "https://issuer.test/tenant-a/token";

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Aud] = TokenEndpoint;

        PrivateKeyJwtClientAuthenticationResult result = PrivateKeyJwtClientAuthentication.Validate(
            payload, ClientId, [Issuer, TokenEndpoint], Now, Skew);

        Assert.IsTrue(result.IsValid, result.FailureReason);
    }


    /// <summary>RFC 7523 §3 item 4: an expired assertion (subject to skew) is rejected.</summary>
    [TestMethod]
    public void ExpiredAssertionIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-5).ToUnixTimeSeconds();

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>"iat sanity": an <c>iat</c> claiming issuance far in the future is rejected.</summary>
    [TestMethod]
    public void AbsurdFutureIssuedAtIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.AddYears(10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddYears(10).AddMinutes(5).ToUnixTimeSeconds();

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>A missing <c>jti</c> is rejected — required for this profile's replay defense.</summary>
    [TestMethod]
    public void MissingJtiIsRejected()
    {
        JwtPayload payload = ValidPayload();
        _ = payload.Remove(WellKnownJwtClaimNames.Jti);

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>RFC 7523 §3 item 5: a future <c>nbf</c> (beyond skew) makes the assertion not yet valid.</summary>
    [TestMethod]
    public void FutureNotBeforeIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = Now.AddMinutes(2).ToUnixTimeSeconds();

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary><c>exp</c> at or before <c>iat</c> is an internally inconsistent, non-positive lifetime.</summary>
    [TestMethod]
    public void ExpiryAtOrBeforeIssuedAtIsRejected()
    {
        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = Now.AddMinutes(-1).ToUnixTimeSeconds();

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid);
    }


    /// <summary>
    /// An <c>exp</c>, <c>iat</c> or <c>nbf</c> whose number names no instant a <see cref="DateTimeOffset"/> can
    /// hold refuses the client assertion as a malformed time claim, and the check answers a result rather than
    /// throwing: the integer 1000000000000000, as the library's decoder hands it (a 64-bit integer), and a number
    /// beyond a 64-bit integer, which the decoder hands as a <see cref="decimal"/>. Each is a NumericDate, and
    /// refusing it is this library's fail-closed reading: no instant the checks compare can hold it.
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

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

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
        payload[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = expiration;

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

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

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(expectedExpiration, result.Expiration);
    }


    /// <summary>
    /// An <c>exp</c>, <c>iat</c> or <c>nbf</c> that is a JSON string holding digits refuses the client assertion
    /// as a malformed time claim, whatever instant the digits would name as a number.
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
    public void ATimeClaimThatIsAJsonStringIsRejected(string claimName, string digits)
    {
        JwtPayload payload = ValidPayload();
        payload[claimName] = digits;

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.IsFalse(result.IsValid, $"The string {digits} was read as the {claimName} claim.");
        Assert.Contains($"{claimName} claim", result.FailureReason!);
        Assert.Contains("malformed", result.FailureReason!);
    }


    /// <summary>
    /// The edge of the skew decides the expiry to the tick: an <c>exp</c> exactly one skew before the clock
    /// refuses the client assertion as expired, and one a tick later (a fraction of 0.0000001 second) is not
    /// expired, its fraction kept.
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
        (object expiration, string? expectedFailureStart, DateTimeOffset? expectedExpiration) = caseName switch
        {
            "atTheEdge" => ((object)edgeSeconds, "The client assertion has expired", (DateTimeOffset?)null),
            "oneTickLater" => (edgeSeconds + 0.0000001m, null, DateTimeOffset.FromUnixTimeSeconds(edgeSeconds).AddTicks(1)),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = Now.AddMinutes(-10).ToUnixTimeSeconds();
        payload[WellKnownJwtClaimNames.Exp] = expiration;

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.AreEqual(expectedFailureStart is null, result.IsValid, result.FailureReason);
        Assert.AreEqual(expectedExpiration, result.Expiration);
        Assert.StartsWith(expectedFailureStart ?? string.Empty, result.FailureReason ?? string.Empty, StringComparison.Ordinal);
    }


    /// <summary>
    /// The edge of the skew decides the not-before to the tick: an <c>nbf</c> exactly one skew after the clock is
    /// in force, and one a tick later (a fraction of 0.0000001 second) refuses the client assertion as not yet
    /// valid.
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
            "oneTickLater" => (edgeSeconds + 0.0000001m, "The client assertion is not yet valid (nbf is in the future beyond the skew tolerance)."),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Nbf] = notBefore;

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.AreEqual(expectedFailure, result.FailureReason);
    }


    /// <summary>
    /// The edge of the skew decides the issue time to the tick: an <c>iat</c> exactly one skew after the clock is
    /// accepted, and one a tick later (a fraction of 0.0000001 second) refuses the client assertion as issued in
    /// the future. Refusing an <c>iat</c> beyond the skew after the clock is this library's check, which no
    /// sentence of RFC 7523 Section 3 states;
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 Section 4.1.6</see>: "The "iat"
    /// (issued at) claim identifies the time at which the JWT was issued."
    /// </summary>
    /// <param name="caseName">The <c>iat</c>: <c>atTheEdge</c> or <c>oneTickLater</c>.</param>
    [TestMethod]
    [DataRow("atTheEdge", DisplayName = "an iat exactly one skew after the clock")]
    [DataRow("oneTickLater", DisplayName = "an iat one tick later than that")]
    public void TheEdgeOfTheSkewDecidesTheIssueTimeToTheTick(string caseName)
    {
        long edgeSeconds = Now.Add(Skew).ToUnixTimeSeconds();
        (object issuedAt, string? expectedFailure) = caseName switch
        {
            "atTheEdge" => ((object)edgeSeconds, (string?)null),
            "oneTickLater" => (edgeSeconds + 0.0000001m, "The client assertion iat is in the future beyond the skew tolerance."),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        JwtPayload payload = ValidPayload();
        payload[WellKnownJwtClaimNames.Iat] = issuedAt;

        PrivateKeyJwtClientAuthenticationResult result = Validate(payload);

        Assert.AreEqual(expectedFailure, result.FailureReason);
    }


    //Part B — the full BuildValidator() pipeline: real compact-JWS parsing, key resolution from a
    //ClientJwks JSON document, real P-256 signature verification, then Validate. TestHostShell supplies
    //a fully-wired EndpointServer (codecs, crypto); the ClientRecord under test is a local `with` copy
    //that is never re-registered with the dispatcher — the delegate is invoked directly, which is the
    //seam this test targets.

    [TestMethod]
    public async Task HappyPathWithProjectCryptoGeneratedKeyAuthenticates()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsTrue(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// distinct <c>kid</c> values within a set a SHOULD, so a duplicate can arrive. A registered key
    /// set carrying two keys under the
    /// SAME <c>kid</c> must refuse the assertion outright — a first-match scan that trusts whichever
    /// element sits first lets whoever controls the array's order pick which key is trusted.
    /// </summary>
    [TestMethod]
    public async Task DuplicateKeyIdInRegisteredSetIsRefused()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        const string DuplicateKeyId = "duplicated-kid";

        var firstKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var secondKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwks = BuildJwksJson(
                    (JwkOf(firstKeys.PublicKey), DuplicateKeyId),
                    (JwkOf(secondKeys.PublicKey), DuplicateKeyId))
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString,
                firstKeys.PrivateKey, DuplicateKeyId).ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated,
                "A key identifier repeated across the registered set must refuse rather than pick a winner.");
        }
        finally
        {
            firstKeys.PublicKey.Dispose();
            firstKeys.PrivateKey.Dispose();
            secondKeys.PublicKey.Dispose();
            secondKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see> makes
    /// <c>kid</c> optional only for a single-key set; a multi-key set with no <c>kid</c> header on the
    /// assertion carries no way to tell which key was meant, so it is refused rather than defaulting
    /// to whichever key sits first in the registered set.
    /// </summary>
    [TestMethod]
    public async Task TwoKeySetWithNoKidHeaderIsRefused()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var firstKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var secondKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwks = BuildJwksJson(
                    (JwkOf(firstKeys.PublicKey), "key-a"),
                    (JwkOf(secondKeys.PublicKey), "key-b"))
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionWithoutKidAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, firstKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated, "A multi-key set with no kid header must refuse, not pick the first key.");
        }
        finally
        {
            firstKeys.PublicKey.Dispose();
            firstKeys.PrivateKey.Dispose();
            secondKeys.PublicKey.Dispose();
            secondKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>: <c>kid</c>
    /// is optional, so a legitimate single-key set with no <c>kid</c> header must still authenticate.
    /// Green both before and after the duplicate/no-kid refusal fix — the regression guard on it.
    /// </summary>
    [TestMethod]
    public async Task SingleKeySetWithNoKidHeaderStillAuthenticates()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionWithoutKidAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsTrue(authenticated,
                "A single-key set with no kid header must still authenticate (RFC 7517 §4.5: kid is optional).");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A rotated set publishing both the old and the new key: the assertion's <c>kid</c> selects the
    /// new key by identifier and authenticates, proving selection tracks the identifier rather than
    /// array position.
    /// </summary>
    [TestMethod]
    public async Task RotatedKeySetSelectsTheNewKeyByKid()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        const string OldKeyId = "old-key";
        const string NewKeyId = "new-key";

        var oldKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var newKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwks = BuildJwksJson(
                    (JwkOf(oldKeys.PublicKey), OldKeyId),
                    (JwkOf(newKeys.PublicKey), NewKeyId))
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString,
                newKeys.PrivateKey, NewKeyId).ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsTrue(authenticated,
                "The current key's kid must select it out of a rotated set that still carries the old key.");
        }
        finally
        {
            oldKeys.PublicKey.Dispose();
            oldKeys.PrivateKey.Dispose();
            newKeys.PublicKey.Dispose();
            newKeys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task TamperedSignatureIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            string[] segments = assertion.Split('.');
            Assert.HasCount(3, segments);
            char firstSignatureChar = segments[2][0];
            char flipped = firstSignatureChar == 'A' ? 'B' : 'A';
            string tampered = string.Join('.', segments[0], segments[1], flipped + segments[2][1..]);

            RequestFields fields = BuildFields(tampered);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// An assertion signed by a DIFFERENT key than the one published in <c>ClientJwks</c> is rejected —
    /// proves the signature check verifies against the REGISTERED key, not merely that some signature
    /// is present.
    /// </summary>
    [TestMethod]
    public async Task AssertionSignedByAnUnregisteredKeyIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var registeredKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var attackerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            //The published JWKS carries the REGISTERED public key; the assertion is signed with the
            //ATTACKER's distinct private key.
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, registeredKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, attackerKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            registeredKeys.PublicKey.Dispose();
            registeredKeys.PrivateKey.Dispose();
            attackerKeys.PublicKey.Dispose();
            attackerKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// RFC 7519 §4: "The JWT Claim Names within a Claims Set MUST be unique." An assertion whose
    /// Claims Set repeats <c>sub</c> — the attacker's value first, the honest client id last — is
    /// refused (401 <c>invalid_client</c> at the token endpoint this delegate feeds) rather than
    /// crashing the caller. Only the payload segment is rebuilt by hand (never through this
    /// repository's serializers) and re-signed with the SAME client private key, so only the
    /// payload's well-formedness gate — not an invalid signature — can be responsible for the
    /// refusal. The call completing and returning <see langword="false"/>, rather than an escaped
    /// exception, is itself part of what this test proves.
    /// </summary>
    [TestMethod]
    public async Task AssertionWithDuplicateSubClaimIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            string[] segments = assertion.Split('.');
            using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(segments[1], BaseMemoryPool.Shared);
            string payloadJson = Encoding.UTF8.GetString(payloadOwner.Memory.Span);

            //Splice an attacker-controlled "sub" ahead of the honest one already in the serialized
            //payload — raw string surgery, not a Dictionary<string,object> round trip, since a
            //dictionary cannot itself carry two entries under the same key.
            string tamperedPayloadJson = payloadJson.Insert(1, "\"sub\":\"attacker-client\",");
            string tamperedPayloadB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(tamperedPayloadJson));

            byte[] signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{tamperedPayloadB64}");
            using Signature signature = await clientKeys.PrivateKey.SignAsync(signingInput, BaseMemoryPool.Shared)
                .ConfigureAwait(false);
            string signatureB64 = TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());
            string tamperedAssertion = $"{segments[0]}.{tamperedPayloadB64}.{signatureB64}";

            RequestFields fields = BuildFields(tamperedAssertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task MissingClientAssertionTypeIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = new();
            fields[OAuthRequestParameterNames.ClientAssertion] = assertion;
            //client_assertion_type deliberately omitted.
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task WrongClientAssertionTypeIsRejected()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = new();
            fields[OAuthRequestParameterNames.ClientAssertionType] = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";
            fields[OAuthRequestParameterNames.ClientAssertion] = assertion;
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    [TestMethod]
    public async Task MissingClientJwksFailsClosed()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            //A confidential-looking registration with no published key material at all.
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated);
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591 §2</see>'s <c>jwks_uri</c>
    /// registration — "URL string referencing the client's JSON Web Key (JWK) Set [RFC7517] document,
    /// which contains the client's public keys... these keys might be used by some applications for
    /// validating signed requests made to the token endpoint when using JWTs for client authentication"
    /// — authenticates once the caller wires the key-set resolution seam.
    /// </summary>
    [TestMethod]
    public async Task RegisteredJwksUriWithAWiredResolutionSeamAuthenticates()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            Uri jwksUri = new("https://client.example/jwks.json");
            string jwksJson = BuildJwksJson((JwkOf(clientKeys.PublicKey), SigningKeyId));

            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwksUri = jwksUri
            };

            ValueTask<JwksUriResolution> ResolveJwksUriAsync(Uri uri, ExchangeContext context, CancellationToken ct) =>
                ValueTask.FromResult(new JwksUriResolution
                {
                    Outcome = JwksUriResolutionOutcome.Resolved,
                    Jwks = jwksJson
                });

            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator(
                resolveJwksUriAsync: ResolveJwksUriAsync);

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsTrue(authenticated,
                "A registration with only a jwks_uri must authenticate once the caller wires a key-set resolution seam.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// The same RFC 7591 §2 <c>jwks_uri</c> registration with NO resolution seam wired fails closed —
    /// the application owns what reaches the wire, so nothing here dereferences <c>jwks_uri</c> on its
    /// own; the refusal is identical to a registration with no key material at all
    /// (<see cref="MissingClientJwksFailsClosed"/>).
    /// </summary>
    [TestMethod]
    public async Task RegisteredJwksUriWithNoResolutionSeamWiredFailsClosed()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = material.Registration with
            {
                TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                ClientJwksUri = new Uri("https://client.example/jwks.json")
            };
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            RequestFields fields = BuildFields(assertion);
            ExchangeContext context = BuildContext(app.Server);

            bool authenticated = await validator(ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, context, TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(authenticated,
                "A jwks_uri registration with no resolution seam wired must fail closed, not dereference it on its own.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// rfc7523bis-11
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
    /// 4</see>'s issuer-only audience rule admits no additional accepted audience: this proves a
    /// contract of this library: <see cref="PrivateKeyJwtClientAuthentication.BuildValidator(System.Collections.Generic.IReadOnlyCollection{string}?,CheckClientAssertionJtiReplayDelegate?,Verifiable.OAuth.Server.Pipeline.ResolveJwksUriDelegate?,ClientAssertionAudiencePolicy?)"/>
    /// refuses the contradictory composition of a non-empty additional-audience set together with
    /// <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/> when the validator is BUILT,
    /// before any wire input is read, through the registry-resolving overload and through the
    /// overload taking an explicit <see cref="VerificationDelegate"/> alike, and the exception's message
    /// names both <c>additionalAcceptedAudiences</c> and <c>audiencePolicy</c>.
    /// </summary>
    /// <param name="isExplicitVerificationDelegateOverload">
    /// <see langword="true"/> to build through the overload taking an explicit
    /// <see cref="VerificationDelegate"/>, <see langword="false"/> for the registry-resolving overload.
    /// </param>
    [TestMethod]
    [DataRow(false, DisplayName = "the registry-resolving overload")]
    [DataRow(true, DisplayName = "the explicit VerificationDelegate overload")]
    public void IssuerOnlyPolicyWithAdditionalAudiencesIsRefusedAtBuild(bool isExplicitVerificationDelegateOverload)
    {
        VerificationDelegate verification = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(
            CryptoAlgorithm.P256, Purpose.Verification);

        ArgumentException refusal = Assert.ThrowsExactly<ArgumentException>(
            () => isExplicitVerificationDelegateOverload
                ? PrivateKeyJwtClientAuthentication.BuildValidator(
                    verification,
                    additionalAcceptedAudiences: ["https://other.example"],
                    audiencePolicy: ClientAssertionAudiencePolicy.IssuerIdentifierOnly)
                : PrivateKeyJwtClientAuthentication.BuildValidator(
                    additionalAcceptedAudiences: ["https://other.example"],
                    audiencePolicy: ClientAssertionAudiencePolicy.IssuerIdentifierOnly));

        Assert.Contains("additionalAcceptedAudiences", refusal.Message, StringComparison.Ordinal,
            "The refusal must name the additional-audience argument.");
        Assert.Contains("audiencePolicy", refusal.Message, StringComparison.Ordinal,
            "The refusal must name the audience-policy argument.");
    }


    /// <summary>
    /// rfc7523bis-11
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
    /// 4</see> item b: "The authorization server MUST have an issuer identifier to be used with this
    /// specification." The validator compares an assertion's <c>aud</c> with the authorization server's
    /// issuer identifier, and when the issuer resolution seam fails with an
    /// <see cref="InvalidOperationException"/> there is no issuer identifier to compare with: a
    /// well-formed assertion, signed by the registered key and authenticating before the seam fails, is
    /// refused by the validator returning <see langword="false"/> rather than by an escaped exception.
    /// </summary>
    [TestMethod]
    public async Task AssertionIsRefusedWhenIssuerResolutionFails()
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();

            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);
            RequestFields fields = BuildFields(assertion);

            bool isAuthenticatedWithAnIssuer = await validator(
                ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, BuildContext(app.Server), TestContext.CancellationToken)
                .ConfigureAwait(false);
            Assert.IsTrue(isAuthenticatedWithAnIssuer,
                "The assertion must authenticate while the issuer resolves, so only the failed resolution can refuse it.");

            await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.ResolveIssuerAsync = (_, _, _) =>
                    throw new InvalidOperationException("The authorization server has no issuer identifier.");
            }).ConfigureAwait(false);

            bool isAuthenticatedWithoutAnIssuer = await validator(
                ClientCredentialReading.Read(RequestHeaders.Empty, fields), registration, BuildContext(app.Server), TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(isAuthenticatedWithoutAnIssuer,
                "A failed issuer resolution leaves no issuer identifier to compare the audience with, so the assertion must be refused.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// rfc7523bis-11
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rfc7523bis-11#section-4">Section
    /// 4</see> item b: the authorization server "MUST reject any JWT that does not contain its issuer
    /// identifier as its sole audience value." RFC 7519
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">Section 4.1.3</see> makes the
    /// <c>aud</c> value "an array of case-sensitive strings" in the general case, and the container a
    /// host's payload deserializer builds for that array is the host's choice. The issuer-only rule
    /// counts an <c>aud</c> array as any <see cref="IEnumerable{T}"/> of <see cref="object"/> or of
    /// <see cref="string"/>, reading its first two elements, so the element count and not the
    /// container type decides: here the deserializer yields the array as a lazily produced sequence
    /// that is neither a list nor an array, holding the issuer identifier once (the sole audience value,
    /// accepted) or twice (not the sole audience value, refused) under
    /// <see cref="ClientAssertionAudiencePolicy.IssuerIdentifierOnly"/>.
    /// </summary>
    /// <param name="issuerElementCount">How many times the issuer identifier appears in the <c>aud</c> sequence.</param>
    /// <param name="isAuthenticatedExpected">Whether the assertion is expected to authenticate.</param>
    [TestMethod]
    [DataRow(1, true, DisplayName = "the issuer identifier once in a lazily produced sequence is accepted")]
    [DataRow(2, false, DisplayName = "the issuer identifier twice in a lazily produced sequence is refused")]
    public async Task IssuerOnlyPolicyCountsAnAudienceSequenceHeldAsAnIterator(int issuerElementCount, bool isAuthenticatedExpected)
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);
            string issuerIdentifier = registration.IssuerUri!.OriginalString;
            string[] audienceElements = [.. Enumerable.Repeat(issuerIdentifier, issuerElementCount)];

            await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.Codecs.JwtPayloadDeserializer = bytes =>
                {
                    Dictionary<string, object> claims = JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                        bytes, TestSetup.DefaultSerializationOptions)
                        ?? throw new FormatException("Payload JSON parsed to null.");
                    claims[WellKnownJwtClaimNames.Aud] = AsLazySequence(audienceElements);

                    return claims;
                };
            }).ConfigureAwait(false);

            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator(
                audiencePolicy: ClientAssertionAudiencePolicy.IssuerIdentifierOnly);
            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, issuerIdentifier, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            bool isAuthenticated = await validator(
                ClientCredentialReading.Read(RequestHeaders.Empty, BuildFields(assertion)), registration, BuildContext(app.Server), TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.AreEqual(isAuthenticatedExpected, isAuthenticated,
                $"An aud sequence holding the issuer identifier {issuerElementCount} time(s) must "
                + (isAuthenticatedExpected ? "authenticate" : "be refused") + " under the issuer-only policy.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Yields <paramref name="values"/> one at a time through an iterator, so the result is an
    /// <see cref="IEnumerable{T}"/> of <see cref="object"/> that is neither an
    /// <see cref="IReadOnlyList{T}"/> nor an array.
    /// </summary>
    /// <param name="values">The elements to yield.</param>
    private static IEnumerable<object> AsLazySequence(string[] values)
    {
        foreach(string value in values)
        {
            yield return value;
        }
    }


    /// <summary>
    /// RFC 7519 <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4">Section 4</see>: "The Claim
    /// Names within a JWT Claims Set MUST be unique; JWT parsers MUST either reject JWTs with duplicate
    /// Claim Names or use a JSON parser that returns only the lexically last duplicate member name".
    /// <see cref="PrivateKeyJwtClientAuthentication"/> takes the rejection branch: it refuses a payload
    /// that repeats a member name through <see cref="JwkJsonReader.IsWellFormedJsonDocument"/> before the
    /// wired payload deserializer or any claim rule runs. Here the wired deserializer is permissive: it
    /// parses with <see cref="JsonDocument"/>, which allows a repeated name, and keeps the first member
    /// (case one, the client's <c>sub</c> first and a foreign <c>sub</c> last) or the last member (case
    /// two, a foreign <c>sub</c> first and the client's <c>sub</c> last). Each case is built so that the
    /// deserializer yields the client's own <c>sub</c>, which the assertion would authenticate with, and
    /// the validator nevertheless refuses the re-signed assertion, so only the refusal of the repeated
    /// name can be responsible.
    /// </summary>
    /// <param name="isLastMemberKept">
    /// Whether the permissive deserializer keeps the last member under a repeated name (otherwise the first).
    /// </param>
    /// <param name="isForeignSubjectFirst">
    /// Whether the foreign <c>sub</c> member precedes the client's (otherwise it follows).
    /// </param>
    [TestMethod]
    [DataRow(false, false, DisplayName = "the client's sub first and a foreign sub last, read first-wins")]
    [DataRow(true, true, DisplayName = "a foreign sub first and the client's sub last, read last-wins")]
    public async Task RepeatedClaimNameIsRefusedBeforeAnyClaimIsRead(bool isLastMemberKept, bool isForeignSubjectFirst)
    {
        await using TestHostShell app = new(new FakeTimeProvider(TestClock.CanonicalEpoch));
        using VerifierKeyMaterial material = await app.RegisterDpopClientAsync(
            ClientId, new Uri(ClientId), profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);

        var clientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            ClientRecord registration = BuildConfidentialRegistration(material.Registration, clientKeys.PublicKey);

            await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.Codecs.JwtPayloadDeserializer = bytes =>
                    ReadClaimsKeepingOneRepeatedMember(bytes, isLastMemberKept);
            }).ConfigureAwait(false);

            ValidateClientCredentialsDelegate validator = PrivateKeyJwtClientAuthentication.BuildValidator();
            string assertion = await SignAssertionAsync(
                app.Server, registration.ClientId, registration.IssuerUri!.OriginalString, clientKeys.PrivateKey)
                .ConfigureAwait(false);

            string[] segments = assertion.Split('.');
            using IMemoryOwner<byte> payloadOwner = TestSetup.Base64UrlDecoder(segments[1], BaseMemoryPool.Shared);
            string payloadJson = Encoding.UTF8.GetString(payloadOwner.Memory.Span);

            //Splice the foreign "sub" in as raw text, since a dictionary cannot carry two entries under one key.
            string foreignSubjectMember = $"\"{WellKnownJwtClaimNames.Sub}\":\"foreign-subject\"";
            string repeatedPayloadJson = isForeignSubjectFirst
                ? payloadJson.Insert(1, foreignSubjectMember + ",")
                : payloadJson.Insert(payloadJson.Length - 1, "," + foreignSubjectMember);
            string repeatedPayloadB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(repeatedPayloadJson));

            byte[] signingInput = Encoding.ASCII.GetBytes($"{segments[0]}.{repeatedPayloadB64}");
            using Signature signature = await clientKeys.PrivateKey.SignAsync(signingInput, BaseMemoryPool.Shared)
                .ConfigureAwait(false);
            string signatureB64 = TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());
            string repeatedAssertion = $"{segments[0]}.{repeatedPayloadB64}.{signatureB64}";

            IReadOnlyDictionary<string, object> permissiveClaims = app.Server.OAuth().Codecs.JwtPayloadDeserializer!(
                Encoding.UTF8.GetBytes(repeatedPayloadJson));
            Assert.AreEqual(registration.ClientId, (string)permissiveClaims[WellKnownJwtClaimNames.Sub],
                "The permissive deserializer must yield the client's own sub, so only the repeated name can refuse the assertion.");

            bool isAuthenticated = await validator(
                ClientCredentialReading.Read(RequestHeaders.Empty, BuildFields(repeatedAssertion)), registration, BuildContext(app.Server), TestContext.CancellationToken)
                .ConfigureAwait(false);

            Assert.IsFalse(isAuthenticated,
                "An assertion whose payload repeats a claim name must be refused whichever member the wired deserializer keeps.");
        }
        finally
        {
            clientKeys.PublicKey.Dispose();
            clientKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Reads a JWT payload with <see cref="JsonDocument"/>, which allows a repeated member name, and keeps
    /// one member per name: the last with the indexer, or the first with
    /// <see cref="Dictionary{TKey, TValue}.TryAdd(TKey, TValue)"/>. Strings, integers and booleans are
    /// materialised as their CLR values and every other value as its raw JSON text.
    /// </summary>
    /// <param name="payload">The decoded UTF-8 bytes of the payload JSON object.</param>
    /// <param name="isLastMemberKept">Whether the last member under a repeated name wins (otherwise the first).</param>
    /// <returns>The claim dictionary holding one value per claim name.</returns>
    private static Dictionary<string, object> ReadClaimsKeepingOneRepeatedMember(ReadOnlySpan<byte> payload, bool isLastMemberKept)
    {
        using JsonDocument document = JsonDocument.Parse(
            payload.ToArray(), new JsonDocumentOptions { AllowDuplicateProperties = true });

        Dictionary<string, object> claims = [];
        foreach(JsonProperty member in document.RootElement.EnumerateObject())
        {
            object value = member.Value.ValueKind switch
            {
                JsonValueKind.String => member.Value.GetString()!,
                JsonValueKind.Number => member.Value.GetInt64(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => member.Value.GetRawText()
            };

            if(isLastMemberKept)
            {
                claims[member.Name] = value;
            }
            else
            {
                _ = claims.TryAdd(member.Name, value);
            }
        }

        return claims;
    }


    /// <summary>
    /// Re-declares <paramref name="baseline"/> for <c>private_key_jwt</c> client authentication: the
    /// token endpoint authentication method is <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/> and
    /// the registered JWK Set holds the one key <paramref name="clientPublicKey"/> under
    /// <see cref="SigningKeyId"/>.
    /// </summary>
    /// <param name="baseline">The registration the host created for the client.</param>
    /// <param name="clientPublicKey">The client's public key to publish in the registered JWK Set.</param>
    /// <returns>The registration with the authentication method and JWK Set replaced.</returns>
    private static ClientRecord BuildConfidentialRegistration(ClientRecord baseline, PublicKeyMemory clientPublicKey)
    {
        string alg = CryptoFormatConversions.DefaultTagToJwaConverter(clientPublicKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            clientPublicKey, alg, TestSetup.Base64UrlEncoder);

        return baseline with
        {
            TokenEndpointAuthMethod = ClientAuthenticationMethod.PrivateKeyJwt,
            ClientJwks = BuildJwksJson((jwk, SigningKeyId))
        };
    }


    /// <summary>
    /// Builds a JWK Set JSON document carrying one key per <paramref name="keys"/> entry, each tagged
    /// with its paired <c>kid</c> — callers pass the same <c>kid</c> twice to build a duplicate-identifier
    /// fixture.
    /// </summary>
    private static string BuildJwksJson(params (IReadOnlyDictionary<string, string> Jwk, string Kid)[] keys)
    {
        StringBuilder sb = new();
        _ = sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[");
        for(int index = 0; index < keys.Length; ++index)
        {
            if(index > 0)
            {
                _ = sb.Append(',');
            }

            _ = sb.Append('{');
            foreach(KeyValuePair<string, string> member in keys[index].Jwk)
            {
                _ = sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
            }

            _ = sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(keys[index].Kid).Append("\"}");
        }

        _ = sb.Append(']').Append('}');

        return sb.ToString();
    }


    private static IReadOnlyDictionary<string, string> JwkOf(PublicKeyMemory publicKey)
    {
        string alg = CryptoFormatConversions.DefaultTagToJwaConverter(publicKey.Tag);

        return DpopJwkUtilities.ToJwk(publicKey, alg, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Signs a client assertion through <see cref="ClientAssertionSigning.SignAsync(string, string, string, DateTimeOffset, DateTimeOffset, PrivateKeyMemory, string, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, BaseMemoryPool, CancellationToken)"/>
    /// with the server's codecs, a fresh <c>jti</c>, and an <c>iat</c> one minute before and an <c>exp</c>
    /// five minutes after the server's fixture clock.
    /// </summary>
    /// <param name="server">The server whose codecs and clock the assertion is built with.</param>
    /// <param name="clientId">The client identifier written as the <c>iss</c> and <c>sub</c> claims.</param>
    /// <param name="audience">The value written as the <c>aud</c> claim.</param>
    /// <param name="clientPrivateKey">The client's private key the assertion is signed with.</param>
    /// <param name="signingKeyId">The <c>kid</c> written to the JOSE header.</param>
    /// <returns>The assertion in JWS Compact Serialization.</returns>
    private async Task<string> SignAssertionAsync(
        EndpointServer server, string clientId, string audience, PrivateKeyMemory clientPrivateKey,
        string signingKeyId = SigningKeyId)
    {
        var oauth = server.OAuth();
        DateTimeOffset now = server.TimeProvider.GetUtcNow();

        return await ClientAssertionSigning.SignAsync(
            clientId,
            audience,
            Guid.NewGuid().ToString("N"),
            now.AddMinutes(-1),
            now.AddMinutes(5),
            clientPrivateKey,
            signingKeyId,
            oauth.Codecs.JwtHeaderSerializer!,
            oauth.Codecs.JwtPayloadSerializer!,
            oauth.Codecs.Encoder!,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Signs a client assertion with no <c>kid</c> header member at all — the RFC 7517 §4.5 optional
    /// case a legitimate single-key set relies on. Mirrors
    /// <see cref="ClientAssertionSigning.SignAsync(string, string, string, DateTimeOffset, DateTimeOffset, PrivateKeyMemory, string, JwtHeaderSerializer, JwtPayloadSerializer, EncodeDelegate, BaseMemoryPool, CancellationToken)"/>'s
    /// header and payload shape, since that method requires a non-empty <c>kid</c> and so cannot
    /// produce this header itself.
    /// </summary>
    private async Task<string> SignAssertionWithoutKidAsync(
        EndpointServer server, string clientId, string audience, PrivateKeyMemory clientPrivateKey)
    {
        var oauth = server.OAuth();
        DateTimeOffset now = server.TimeProvider.GetUtcNow();
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(clientPrivateKey.Tag);

        JwtHeader header = new(capacity: 2)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
        };

        JwtPayload payload = new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = clientId,
            [WellKnownJwtClaimNames.Sub] = clientId,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [WellKnownJwtClaimNames.Iat] = now.AddMinutes(-1).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = now.AddMinutes(5).ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            clientPrivateKey,
            oauth.Codecs.JwtHeaderSerializer!,
            oauth.Codecs.JwtPayloadSerializer!,
            oauth.Codecs.Encoder!,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, oauth.Codecs.Encoder!);
    }


    /// <summary>
    /// Builds the form fields of a <c>private_key_jwt</c> request: the <c>client_assertion_type</c> set to
    /// <see cref="WellKnownClientAssertionTypes.JwtBearer"/> and the <c>client_assertion</c> set to
    /// <paramref name="clientAssertion"/>.
    /// </summary>
    /// <param name="clientAssertion">The assertion in JWS Compact Serialization.</param>
    /// <returns>The request fields carrying the assertion type and the assertion.</returns>
    private static RequestFields BuildFields(string clientAssertion)
    {
        RequestFields fields = new();
        fields[OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer;
        fields[OAuthRequestParameterNames.ClientAssertion] = clientAssertion;

        return fields;
    }


    /// <summary>
    /// Builds an <see cref="ExchangeContext"/> bound to <paramref name="server"/>, the shape a dispatched
    /// request carries into a <see cref="ValidateClientCredentialsDelegate"/>.
    /// </summary>
    /// <param name="server">The server the context is bound to.</param>
    /// <returns>The context with the server set.</returns>
    private static ExchangeContext BuildContext(EndpointServer server)
    {
        ExchangeContext context = [];
        context.SetServer(server);

        return context;
    }
}
