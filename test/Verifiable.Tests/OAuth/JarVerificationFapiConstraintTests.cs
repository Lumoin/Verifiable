using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Jar;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Direct tests for the <see cref="JarVerification"/> temporal constraints that
/// FAPI 2.0 Message Signing §5.3.1 requires of signed request objects at the PAR
/// endpoint: a bounded <c>nbf</c> age, a bounded <c>exp</c> window measured from
/// <c>nbf</c>, and the <c>oauth-authz-req+jwt</c> <c>typ</c> header.
/// </summary>
[TestClass]
internal sealed class JarVerificationFapiConstraintTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(5);

    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromSeconds(60);

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtHeaderDeserializer HeaderDeserializer =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("Header JSON parsed to null.");

    private static readonly JwtPayloadDeserializer PayloadDeserializer =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("Payload JSON parsed to null.");


    [TestMethod]
    public async Task AcceptsJarWithinAllTemporalCeilings()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verificationKey = keys.PublicKey;
        using PrivateKeyMemory signingKey = keys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string jar = await MintJarAsync(
            signingKey, iat: now, nbf: now, exp: now.AddSeconds(30)).ConfigureAwait(false);

        JarVerificationResult result = await VerifyAsync(jar, verificationKey).ConfigureAwait(false);

        Assert.IsInstanceOfType<JarVerified>(result);
    }


    [TestMethod]
    public async Task RejectsBackdatedNbfBeyondTheMaximumLifetime()
    {
        //FAPI 2.0 MS §5.3.1: nbf no longer than the bounded interval in the past. A
        //freshly signed (iat = now) request object carrying a backdated nbf would
        //otherwise open a stale validity window.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verificationKey = keys.PublicKey;
        using PrivateKeyMemory signingKey = keys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string jar = await MintJarAsync(
            signingKey, iat: now, nbf: now.AddMinutes(-10), exp: now.AddSeconds(30)).ConfigureAwait(false);

        JarVerificationResult result = await VerifyAsync(jar, verificationKey).ConfigureAwait(false);

        Assert.IsInstanceOfType<JarRejected>(result);
        Assert.AreEqual(OAuthErrors.InvalidRequestObject, ((JarRejected)result).ErrorCode);
    }


    [TestMethod]
    public async Task RejectsExpWindowExceedingTheMaximumLifetimeFromNbf()
    {
        //FAPI 2.0 MS §5.3.1 phrases the exp window from nbf: a slightly backdated nbf
        //must not stretch the validity window past the ceiling even when exp - iat
        //stays within it.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verificationKey = keys.PublicKey;
        using PrivateKeyMemory signingKey = keys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string jar = await MintJarAsync(
            signingKey, iat: now, nbf: now.AddSeconds(-45), exp: now.AddSeconds(30)).ConfigureAwait(false);

        JarVerificationResult result = await VerifyAsync(jar, verificationKey).ConfigureAwait(false);

        Assert.IsInstanceOfType<JarRejected>(result);
        Assert.Contains("nbf", ((JarRejected)result).Reason);
    }


    [TestMethod]
    public async Task RejectsMissingOauthAuthzReqJwtTyp()
    {
        //FAPI 2.0 MS §5.3.1 / RFC 9101 §10.8: only typ oauth-authz-req+jwt is accepted.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verificationKey = keys.PublicKey;
        using PrivateKeyMemory signingKey = keys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader plainJwtHeader = new(capacity: 2)
        {
            [WellKnownJwkMemberNames.Alg] = algorithm,
            [WellKnownJoseHeaderNames.Typ] = WellKnownJwkValues.TypeJwt
        };
        string jar = await SignAsync(
            signingKey, plainJwtHeader, iat: now, nbf: now, exp: now.AddSeconds(30)).ConfigureAwait(false);

        JarVerificationResult result = await VerifyAsync(jar, verificationKey).ConfigureAwait(false);

        Assert.IsInstanceOfType<JarRejected>(result);
        Assert.Contains(WellKnownMediaTypes.Jwt.OauthAuthzReqJwt, ((JarRejected)result).Reason);
    }


    private async ValueTask<string> MintJarAsync(
        PrivateKeyMemory signingKey, DateTimeOffset iat, DateTimeOffset nbf, DateTimeOffset exp)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeaderExtensions.ForJar(algorithm, "jar-key-1");

        return await SignAsync(signingKey, header, iat, nbf, exp).ConfigureAwait(false);
    }


    private async ValueTask<string> SignAsync(
        PrivateKeyMemory signingKey,
        JwtHeader header,
        DateTimeOffset iat,
        DateTimeOffset nbf,
        DateTimeOffset exp)
    {
        JwtPayload payload = new(capacity: 4)
        {
            [WellKnownJwtClaimNames.ClientId] = "https://client.example.org",
            [WellKnownJwtClaimNames.Iat] = iat.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Nbf] = nbf.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = exp.ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    private async ValueTask<JarVerificationResult> VerifyAsync(
        string jar, PublicKeyMemory verificationKey) =>
        await JarVerification.VerifyAsync(
            jar,
            verificationKey,
            TimeProvider.GetUtcNow(),
            ClockSkew,
            MaximumLifetime,
            TestSetup.Base64UrlDecoder,
            HeaderDeserializer,
            PayloadDeserializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);
}
