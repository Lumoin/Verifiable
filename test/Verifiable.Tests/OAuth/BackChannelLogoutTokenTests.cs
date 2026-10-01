using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Logout;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Firewalled round-trip tests for the OIDC Back-Channel Logout 1.0 Logout Token
/// primitives: the OP builds and signs a Logout Token, and an RP reconstructs it from the
/// compact wire string alone (plus the OP's published public key), running full signature +
/// §2.6 validation. Nothing in-memory is shared across the boundary.
/// </summary>
[TestClass]
internal sealed class BackChannelLogoutTokenTests
{
    private const string Issuer = "https://op.example/";
    private const string Audience = "https://rp.example/client";
    private const string Subject = "subject-bcl-1";
    private const string SessionId = "session-bcl-1";

    public TestContext TestContext { get; set; } = null!;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static DateTimeOffset IssuedAt { get; } = DateTimeOffset.UnixEpoch.AddSeconds(1715305159);


    /// <summary>Happy path: a Logout Token carrying both sub and sid round-trips and both are extracted.</summary>
    [TestMethod]
    public async Task LogoutTokenRoundTripsWithSubAndSid()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        string compact = await IssueAsync(opPrivate, Subject, SessionId).ConfigureAwait(false);

        //RP side: only the wire string and the OP's published public key.
        BackChannelLogoutVerificationResult result = await VerifyAsync(compact, opPublic).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Expected a valid Logout Token, got {result.Error}.");
        Assert.AreEqual(Subject, result.Subject);
        Assert.AreEqual(SessionId, result.SessionId);
    }


    /// <summary>§2.4: a sid-only Logout Token is valid (terminate by session).</summary>
    [TestMethod]
    public async Task LogoutTokenRoundTripsWithSidOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        string compact = await IssueAsync(opPrivate, subject: null, sessionId: SessionId).ConfigureAwait(false);

        BackChannelLogoutVerificationResult result = await VerifyAsync(compact, opPublic).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Expected a valid Logout Token, got {result.Error}.");
        Assert.IsNull(result.Subject);
        Assert.AreEqual(SessionId, result.SessionId);
    }


    /// <summary>§2.4: a sub-only Logout Token is valid (terminate every session of the subject).</summary>
    [TestMethod]
    public async Task LogoutTokenRoundTripsWithSubOnly()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        string compact = await IssueAsync(opPrivate, subject: Subject, sessionId: null).ConfigureAwait(false);

        BackChannelLogoutVerificationResult result = await VerifyAsync(compact, opPublic).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Expected a valid Logout Token, got {result.Error}.");
        Assert.AreEqual(Subject, result.Subject);
        Assert.IsNull(result.SessionId);
    }


    /// <summary>§2.4: building a Logout Token with neither sub nor sid is rejected at the source.</summary>
    [TestMethod]
    public async Task BuildRejectsMissingSubjectAndSession()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await IssueAsync(opPrivate, subject: null, sessionId: null).ConfigureAwait(false))
            .ConfigureAwait(false);
    }


    /// <summary>
    /// A Logout Token's <c>sub</c> Claim names the End-User whose sessions end
    /// (<see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">OpenID Connect
    /// Back-Channel Logout 1.0 Section 2.4</see>). A subject that is empty or white space only names no End-User,
    /// so building a Logout Token with it and a <c>sid</c> throws <see cref="ArgumentException"/> for
    /// <c>subject</c>, as the builder throws for its other arguments, and no token carries a blank <c>sub</c> or is
    /// built without the <c>sub</c> its caller gave. The rule is this library's.
    /// </summary>
    /// <param name="subject">The blank subject: the empty string or one space.</param>
    [TestMethod]
    [DataRow("", DisplayName = "an empty subject")]
    [DataRow(" ", DisplayName = "a subject of one space")]
    public async Task BuildRejectsABlankSubject(string subject)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await IssueAsync(opPrivate, subject: subject, sessionId: SessionId).ConfigureAwait(false))
            .ConfigureAwait(false);
        Assert.AreEqual("subject", exception.ParamName);
    }


    /// <summary>
    /// A Logout Token's <c>sid</c> Claim names the session that ends
    /// (<see href="https://openid.net/specs/openid-connect-backchannel-1_0.html#LogoutToken">OpenID Connect
    /// Back-Channel Logout 1.0 Section 2.4</see>). A session identifier that is empty or white space only names no
    /// session, so building a Logout Token with it throws <see cref="ArgumentException"/> for <c>sessionId</c>,
    /// whatever the subject is, as the builder throws for a blank subject: with no subject, and with a subject,
    /// where the token would otherwise carry that <c>sub</c> beside a blank <c>sid</c> or none. No token carries a
    /// blank <c>sid</c> or is built without the <c>sid</c> its caller gave. The rule is this library's.
    /// </summary>
    /// <param name="sessionId">The blank session identifier: the empty string or one space.</param>
    /// <param name="subject">The subject given beside it: none, or the class's subject.</param>
    [TestMethod]
    [DataRow("", null, DisplayName = "an empty session identifier")]
    [DataRow(" ", null, DisplayName = "a session identifier of one space")]
    [DataRow("", Subject, DisplayName = "an empty session identifier beside a subject")]
    [DataRow(" ", Subject, DisplayName = "a session identifier of one space beside a subject")]
    public async Task BuildRejectsABlankSessionId(string sessionId, string? subject)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await IssueAsync(opPrivate, subject: subject, sessionId: sessionId).ConfigureAwait(false))
            .ConfigureAwait(false);
        Assert.AreEqual("sessionId", exception.ParamName);
    }


    /// <summary>§2.6: a Logout Token signed by another key (not the expected OP) is rejected.</summary>
    [TestMethod]
    public async Task WrongSigningKeyIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> opKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory opPrivate = opKeys.PrivateKey;
        using PublicKeyMemory opPublic = opKeys.PublicKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> impostorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory impostorPublic = impostorKeys.PublicKey;
        using PrivateKeyMemory impostorPrivate = impostorKeys.PrivateKey;

        string compact = await IssueAsync(opPrivate, Subject, SessionId).ConfigureAwait(false);

        //Verify against a different public key than the one that signed it.
        BackChannelLogoutVerificationResult result = await VerifyAsync(compact, impostorPublic).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(BackChannelLogoutValidationError.SignatureInvalid, result.Error);
    }


    /// <summary>§2.6: the iss claim MUST equal the expected OP issuer.</summary>
    [TestMethod]
    public async Task WrongIssuerIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        string compact = await IssueAsync(opPrivate, Subject, SessionId).ConfigureAwait(false);

        BackChannelLogoutVerificationResult result =
            await VerifyAsync(compact, opPublic, issuer: "https://impostor.example/").ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(BackChannelLogoutValidationError.IssuerMismatch, result.Error);
    }


    /// <summary>§2.6: the aud claim MUST include this RP's identifier.</summary>
    [TestMethod]
    public async Task WrongAudienceIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        string compact = await IssueAsync(opPrivate, Subject, SessionId).ConfigureAwait(false);

        BackChannelLogoutVerificationResult result =
            await VerifyAsync(compact, opPublic, audience: "https://other.example/client").ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(BackChannelLogoutValidationError.AudienceMismatch, result.Error);
    }


    /// <summary>§2.6: a Logout Token containing a nonce MUST be rejected.</summary>
    [TestMethod]
    public async Task NoncePresentIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        //A correctly-signed token that — against the rules — carries a nonce.
        var payload = new JwtPayload(7)
        {
            [WellKnownJwtClaimNames.Iss] = Issuer,
            [WellKnownJwtClaimNames.Aud] = Audience,
            [WellKnownJwtClaimNames.Iat] = IssuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [WellKnownJwtClaimNames.Sub] = Subject,
            [SecurityEventTokenClaimNames.Events] = LogoutEvents(),
            [WellKnownJwtClaimNames.Nonce] = "should-not-be-here"
        };
        string compact = await SignAsync(opPrivate, payload).ConfigureAwait(false);

        BackChannelLogoutVerificationResult result = await VerifyAsync(compact, opPublic).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(BackChannelLogoutValidationError.ForbiddenNonce, result.Error);
    }


    /// <summary>§2.6: a token whose events claim lacks the back-channel logout member is rejected.</summary>
    [TestMethod]
    public async Task MissingLogoutEventIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory opPublic = keys.PublicKey;
        using PrivateKeyMemory opPrivate = keys.PrivateKey;

        //A correctly-signed token whose events object carries an unrelated member only.
        var payload = new JwtPayload(6)
        {
            [WellKnownJwtClaimNames.Iss] = Issuer,
            [WellKnownJwtClaimNames.Aud] = Audience,
            [WellKnownJwtClaimNames.Iat] = IssuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [WellKnownJwtClaimNames.Sub] = Subject,
            [SecurityEventTokenClaimNames.Events] = new Dictionary<string, object>(1, StringComparer.Ordinal)
            {
                ["https://example.com/unrelated-event"] = new Dictionary<string, object>(0, StringComparer.Ordinal)
            }
        };
        string compact = await SignAsync(opPrivate, payload).ConfigureAwait(false);

        BackChannelLogoutVerificationResult result = await VerifyAsync(compact, opPublic).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(BackChannelLogoutValidationError.MissingLogoutEvent, result.Error);
    }


    /// <summary>Builds the §2.4 events claim carrying the back-channel logout member (empty object).</summary>
    private static Dictionary<string, object> LogoutEvents() => new(1, StringComparer.Ordinal)
    {
        [BackChannelLogout.BackChannelLogoutEventType] = new Dictionary<string, object>(0, StringComparer.Ordinal)
    };


    private async Task<string> IssueAsync(PrivateKeyMemory signingKey, string? subject, string? sessionId) =>
        await BackChannelLogout.BuildLogoutTokenAsync(
            Issuer,
            Audience,
            jwtId: Guid.NewGuid().ToString("N"),
            issuedAt: IssuedAt,
            subject: subject,
            sessionId: sessionId,
            signingKey,
            TestSetup.Base64UrlEncoder,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            Pool,
            cancellationToken: TestContext.CancellationToken,
            signingKeyId: "key-1").ConfigureAwait(false);


    private async Task<BackChannelLogoutVerificationResult> VerifyAsync(
        string compact, PublicKeyMemory publicKey, string? issuer = null, string? audience = null) =>
        await BackChannelLogout.VerifyLogoutTokenAsync(
            compact,
            publicKey,
            issuer ?? Issuer,
            audience ?? Audience,
            TestSetup.Base64UrlDecoder,
            bytes => SecurityEventTestJson.DeserializePart(bytes),
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>Signs an arbitrary payload as a logout+jwt — used to craft §2.6-violating tokens the builder never emits.</summary>
    private async Task<string> SignAsync(PrivateKeyMemory signingKey, JwtPayload payload)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        var header = new JwtHeader(3)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.LogoutJwt,
            [WellKnownJwkMemberNames.Kid] = "key-1"
        };

        var unsigned = new UnsignedJwt(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }
}
