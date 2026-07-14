using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.SecurityEvents;
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

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly DateTimeOffset IssuedAt = DateTimeOffset.UnixEpoch.AddSeconds(1715305159);


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

        await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await IssueAsync(opPrivate, subject: null, sessionId: null).ConfigureAwait(false))
            .ConfigureAwait(false);
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
