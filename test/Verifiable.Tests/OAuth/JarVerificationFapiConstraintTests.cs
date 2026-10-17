using Microsoft.Extensions.Time.Testing;
using System.Text;
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

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static TimeSpan ClockSkew { get; } = TimeSpan.FromSeconds(5);

    private static TimeSpan MaximumLifetime { get; } = TimeSpan.FromSeconds(60);

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    private static JwtHeaderDeserializer HeaderDeserializer { get; } =
        static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
            ?? throw new FormatException("Header JSON parsed to null.");

    private static JwtPayloadDeserializer PayloadDeserializer { get; } =
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

        _ = Assert.IsInstanceOfType<JarVerified>(result);
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

        _ = Assert.IsInstanceOfType<JarRejected>(result);
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

        _ = Assert.IsInstanceOfType<JarRejected>(result);
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

        _ = Assert.IsInstanceOfType<JarRejected>(result);
        Assert.Contains(WellKnownMediaTypes.Jwt.OauthAuthzReqJwt, ((JarRejected)result).Reason);
    }


    /// <summary>
    /// RFC 7519 §4: "The JWT Claim Names within a Claims Set MUST be unique." A payload that
    /// repeats <c>client_id</c> — the attacker's value first, the honest value last — is refused
    /// with the ordinary request-object rejection, never an escaped exception. The payload is
    /// built by hand (never through <see cref="PayloadSerializer"/>, since a
    /// <c>Dictionary&lt;string,object&gt;</c> cannot itself carry two entries under the same key)
    /// and signed over its exact bytes, so only the payload's well-formedness gate — not an
    /// invalid signature — can be responsible for the refusal.
    /// </summary>
    [TestMethod]
    public async Task RejectsPayloadWithDuplicateClientIdClaim()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory verificationKey = keys.PublicKey;
        using PrivateKeyMemory signingKey = keys.PrivateKey;

        DateTimeOffset now = TimeProvider.GetUtcNow();
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeaderExtensions.ForJar(algorithm, "jar-key-1");
        string headerB64 = TestSetup.Base64UrlEncoder(HeaderSerializer(header));

        string payloadJson =
            "{\"client_id\":\"attacker-client\",\"client_id\":\"https://client.example.org\"," +
            $"\"iat\":{now.ToUnixTimeSeconds()},\"nbf\":{now.ToUnixTimeSeconds()},\"exp\":{now.AddSeconds(30).ToUnixTimeSeconds()}}}";
        string payloadB64 = TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson));

        byte[] signingInput = Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}");
        using var signature = await signingKey.SignAsync(signingInput, Pool, TestContext.CancellationToken).ConfigureAwait(false);
        string signatureB64 = TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan());
        string jar = $"{headerB64}.{payloadB64}.{signatureB64}";

        JarVerificationResult result = await VerifyAsync(jar, verificationKey).ConfigureAwait(false);

        _ = Assert.IsInstanceOfType<JarRejected>(result);
        Assert.AreEqual(OAuthErrors.InvalidRequestObject, ((JarRejected)result).ErrorCode);
        Assert.Contains("duplicate", ((JarRejected)result).Reason);
    }


    /// <summary>
    /// RFC 7519 Section 2: a request object's <c>iat</c>, <c>nbf</c> and <c>exp</c> are NumericDates, which may carry a fraction,
    /// each judged to the tick under the clock-skew tolerance. An <c>iat</c> three quarters of a second past the present plus the
    /// tolerance is issued in the future and refused, where a reading at the whole second would take it down to the bound and
    /// admit it; an <c>iat</c> and an <c>nbf</c> a quarter of a second inside the bound, and an <c>exp</c> half a second into its
    /// second, are admitted as the instants written.
    /// </summary>
    [TestMethod]
    public async Task ARequestObjectsFractionalDatesAreJudgedToTheTickAtTheTolerance()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using var verificationKey = keys.PublicKey;
        using var signingKey = keys.PrivateKey;

        var bound = TimeProvider.GetUtcNow().ToUnixTimeSeconds() + (long)ClockSkew.TotalSeconds;

        var pastTheTolerance = await SignWithDatesAsync(
            signingKey, iat: bound + 0.75m, nbf: bound - 1, exp: bound + 30).ConfigureAwait(false);
        var refused = Assert.IsInstanceOfType<JarRejected>(
            await VerifyAsync(pastTheTolerance, verificationKey).ConfigureAwait(false));

        Assert.AreEqual(OAuthErrors.InvalidRequestObject, refused.ErrorCode);
        Assert.Contains("is in the future beyond clock skew", refused.Reason, StringComparison.Ordinal,
            "An iat three quarters of a second past the tolerance is issued in the future.");

        var insideTheTolerance = await SignWithDatesAsync(
            signingKey, iat: bound - 0.25m, nbf: bound - 0.25m, exp: bound + 30.5m).ConfigureAwait(false);
        var admitted = Assert.IsInstanceOfType<JarVerified>(
            await VerifyAsync(insideTheTolerance, verificationKey).ConfigureAwait(false));

        var boundInstant = DateTimeOffset.FromUnixTimeSeconds(bound);
        Assert.AreEqual(boundInstant.AddMilliseconds(-250), admitted.Iat, "The iat is the instant written, to the tick.");
        Assert.AreEqual(boundInstant.AddMilliseconds(-250), admitted.Nbf, "The nbf is the instant written, to the tick.");
        Assert.AreEqual(boundInstant.AddSeconds(30).AddMilliseconds(500), admitted.Exp, "The exp is the instant written, to the tick.");
    }


    /// <summary>Signs a request object whose dates are the counts of seconds given, a fraction written as it is.</summary>
    /// <param name="signingKey">The key the request object is signed with.</param>
    /// <param name="iat">The <c>iat</c>, in seconds since the epoch.</param>
    /// <param name="nbf">The <c>nbf</c>, in seconds since the epoch.</param>
    /// <param name="exp">The <c>exp</c>, in seconds since the epoch.</param>
    /// <returns>The compact request object.</returns>
    private async ValueTask<string> SignWithDatesAsync(PrivateKeyMemory signingKey, decimal iat, decimal nbf, decimal exp)
    {
        var algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        var payload = new JwtPayload(capacity: 4)
        {
            [WellKnownJwtClaimNames.ClientId] = "https://client.example.org",
            [WellKnownJwtClaimNames.Iat] = iat,
            [WellKnownJwtClaimNames.Nbf] = nbf,
            [WellKnownJwtClaimNames.Exp] = exp
        };

        var unsigned = new UnsignedJwt(JwtHeaderExtensions.ForJar(algorithm, "jar-key-1"), payload);
        using var jws = await unsigned.SignAsync(
            signingKey,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
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
