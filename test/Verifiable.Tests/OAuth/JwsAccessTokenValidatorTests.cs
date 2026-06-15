using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

[TestClass]
internal sealed class JwsAccessTokenValidatorTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string DefaultIssuer = "https://issuer.test/tenant-a";
    private const string DefaultAudience = "test-resource-server";
    private const string DefaultSubject = "user-1";
    private const string DefaultClientId = "client-1";
    private const string DefaultKid = "test-kid";
    private const string DefaultScope = "openid profile";

    private static readonly DateTimeOffset NowInstant = new(2026, 5, 17, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan IatSkew = TimeSpan.FromSeconds(60);

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    [TestMethod]
    public async Task ValidatorAcceptsWellFormedAccessToken()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, BuildPayload()).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.IsNotNull(result.Claims);
        Assert.AreEqual(DefaultSubject, result.Claims.Subject);
        Assert.AreEqual(DefaultIssuer, result.Claims.Issuer);
        Assert.AreEqual(DefaultClientId, result.Claims.ClientId);
        Assert.AreEqual(DefaultScope, result.Claims.Scope);
        Assert.HasCount(1, result.Claims.Audience);
        Assert.AreEqual(DefaultAudience, result.Claims.Audience[0]);
    }


    [TestMethod]
    public async Task ValidatorRejectsMalformedToken()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        JwsAccessTokenValidationResult result = await ValidateAsync("not.a.jwt.too.many.parts", keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsAlgNoneHeader()
    {
        //Build a token with alg=none in the header. Signature segment is the
        //empty string per RFC 7515 §4.1.1 / RFC 8725 §3.1.
        string headerJson = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["alg"] = "none",
            ["typ"] = "at+jwt",
            ["kid"] = DefaultKid
        });
        string payloadJson = JsonSerializer.Serialize(BuildPayloadDict());
        string token = string.Concat(
            TestSetup.Base64UrlEncoder(System.Text.Encoding.UTF8.GetBytes(headerJson)),
            ".",
            TestSetup.Base64UrlEncoder(System.Text.Encoding.UTF8.GetBytes(payloadJson)),
            ".",
            TestSetup.Base64UrlEncoder([0x00]));

        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.AlgorithmNotAllowed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsUnknownKid()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, BuildPayload()).ConfigureAwait(false);

        //Resolver returns null for any kid — simulating an unknown key.
        ServerVerificationKeyResolverDelegate resolver = (kid, tenant, ctx, ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(null);

        JwsAccessTokenValidationResult result = await ValidateInternalAsync(token, resolver).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.UnknownKid, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsTamperedSignature()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, BuildPayload()).ConfigureAwait(false);

        //Flip a middle character of the signature segment so it still
        //base64url-decodes but verifies as false.
        int signatureStart = token.LastIndexOf('.') + 1;
        int tamperIndex = signatureStart + (token.Length - signatureStart) / 2;
        char tampered = token[tamperIndex] == 'A' ? 'B' : 'A';
        string tamperedToken = string.Concat(
            token.AsSpan(0, tamperIndex), tampered.ToString(), token.AsSpan(tamperIndex + 1));

        JwsAccessTokenValidationResult result = await ValidateAsync(tamperedToken, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.SignatureFailed, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsIssuerMismatch()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildPayload(issuer: "https://other-issuer.test/tenant-b");
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.IssuerMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsAudienceMismatch()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildPayload(audience: ["other-resource-server"]);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.AudienceMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorAcceptsAudienceArrayContainingExpected()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string[] auds = ["other-rs", DefaultAudience, "third-rs"];
        JwtPayload payload = BuildPayload(audience: auds);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.HasCount(3, result.Claims!.Audience);
    }


    [TestMethod]
    public async Task ValidatorRejectsExpiredToken()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildPayload(
            issuedAt: NowInstant - TimeSpan.FromHours(2),
            expiresAt: NowInstant - TimeSpan.FromHours(1));
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Expired, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsTokenIssuedInFuture()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildPayload(
            issuedAt: NowInstant + TimeSpan.FromHours(2),
            expiresAt: NowInstant + TimeSpan.FromHours(3));
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.IssuedInFuture, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorExtractsCnfJktBindingIntoConfirmation()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        const string expectedThumbprint = "abcdef0123456789-thumbprint-test-value";

        JwtPayload payload = BuildPayload();
        payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
        {
            [WellKnownJwtClaimNames.JwkThumbprint] = expectedThumbprint
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.IsNotNull(result.Claims!.Confirmation);
        Assert.AreEqual(expectedThumbprint, result.Claims.Confirmation!.JwkThumbprint);
    }


    [TestMethod]
    public async Task ValidatorRejectsAuthorizedPartyMismatch()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildPayload();
        payload[WellKnownJwtClaimNames.Azp] = "some-other-client";
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(
            token, keys.PublicKey, expectedAuthorizedParty: "my-client").ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.AuthorizedPartyMismatch, result.FailureReason,
            "A present azp that is not the expected authorized party must be rejected (OIDC §3.1.3.7).");
    }


    [TestMethod]
    public async Task ValidatorAcceptsAndSurfacesMatchingAuthorizedParty()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string[] auds = ["other-rs", DefaultAudience];
        JwtPayload payload = BuildPayload(audience: auds);
        payload[WellKnownJwtClaimNames.Azp] = "my-client";
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(
            token, keys.PublicKey, expectedAuthorizedParty: "my-client").ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.AreEqual("my-client", result.Claims!.AuthorizedParty);
    }


    [TestMethod]
    public async Task ValidatorRejectsMultiAudienceWithoutAuthorizedParty()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string[] auds = ["other-rs", DefaultAudience];
        JwtPayload payload = BuildPayload(audience: auds);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(
            token, keys.PublicKey, expectedAuthorizedParty: "my-client").ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.AuthorizedPartyMissing, result.FailureReason,
            "A multi-audience token without azp must be rejected when an authorized party is expected (OIDC §3.1.3.7).");
    }


    [TestMethod]
    public async Task ValidatorDoesNotEnforceAzpWhenNoExpectedAuthorizedParty()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string[] auds = ["other-rs", DefaultAudience];
        JwtPayload payload = BuildPayload(audience: auds);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        //No expected authorized party supplied: azp is not enforced even with multiple audiences.
        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
    }


    [TestMethod]
    public async Task ValidatorRejectsExpiryAtOrBeforeIssuance()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildPayload(
            issuedAt: NowInstant + TimeSpan.FromMinutes(2),
            expiresAt: NowInstant + TimeSpan.FromMinutes(1));
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.InconsistentTemporalClaims, result.FailureReason,
            "exp at or before iat is a non-positive lifetime and must be rejected regardless of the clock.");
    }


    [TestMethod]
    public async Task ValidatorRejectsNotBeforeAtOrAfterExpiry()
    {
        //exp 30s out, nbf 60s out (== skew, so not NotYetValid) — exp <= nbf, the window never opens.
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildPayload(expiresAt: NowInstant + TimeSpan.FromSeconds(30));
        payload[WellKnownJwtClaimNames.Nbf] = (NowInstant + TimeSpan.FromSeconds(60)).ToUnixTimeSeconds();
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.InconsistentTemporalClaims, result.FailureReason,
            "exp at or before nbf means the validity window never opens and must be rejected.");
    }


    private static JwtPayload BuildPayload(
        string subject = DefaultSubject,
        string? issuer = DefaultIssuer,
        IReadOnlyList<string>? audience = null,
        DateTimeOffset? issuedAt = null,
        DateTimeOffset? expiresAt = null)
    {
        audience ??= [DefaultAudience];
        issuedAt ??= NowInstant - TimeSpan.FromMinutes(1);
        expiresAt ??= NowInstant + TimeSpan.FromHours(1);

        return JwtPayloadExtensions.ForAccessToken(
            subject: subject,
            jti: Guid.NewGuid().ToString("N"),
            scope: DefaultScope,
            issuedAt: issuedAt.Value,
            expiresAt: expiresAt.Value,
            issuer: issuer,
            audience: audience,
            clientId: DefaultClientId);
    }


    private static Dictionary<string, object> BuildPayloadDict()
    {
        Dictionary<string, object> dict = new(StringComparer.Ordinal)
        {
            ["sub"] = DefaultSubject,
            ["iss"] = DefaultIssuer,
            ["aud"] = DefaultAudience,
            ["iat"] = (NowInstant - TimeSpan.FromMinutes(1)).ToUnixTimeSeconds(),
            ["exp"] = (NowInstant + TimeSpan.FromHours(1)).ToUnixTimeSeconds(),
            ["scope"] = DefaultScope,
            ["client_id"] = DefaultClientId,
            ["jti"] = Guid.NewGuid().ToString("N"),
        };
        return dict;
    }


    private async Task<string> BuildSignedAccessTokenAsync(PrivateKeyMemory privateKey, JwtPayload payload)
    {
        JwtHeader header = JwtHeaderExtensions.ForAccessToken(WellKnownJwaValues.Es256, DefaultKid);
        UnsignedJwt unsignedJwt = new(header, payload);

        using JwsMessage jws = await unsignedJwt.SignAsync(
            privateKey,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    private async Task<JwsAccessTokenValidationResult> ValidateAsync(
        string token, PublicKeyMemory publicKey, string? expectedAuthorizedParty = null)
    {
        ServerVerificationKeyResolverDelegate resolver = (kid, tenant, ctx, ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(string.Equals(kid.Value, DefaultKid, StringComparison.Ordinal)
                ? publicKey : null);
        return await ValidateInternalAsync(token, resolver, expectedAuthorizedParty).ConfigureAwait(false);
    }


    private async Task<JwsAccessTokenValidationResult> ValidateInternalAsync(
        string token, ServerVerificationKeyResolverDelegate resolver, string? expectedAuthorizedParty = null)
    {
        return await JwsAccessTokenValidator.ValidateAsync(
            token,
            DefaultIssuer,
            DefaultAudience,
            resolver,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            tenantId: default,
            new ExchangeContext(),
            expectedAuthorizedParty,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static ReadOnlySpan<byte> HeaderSerializer(JwtHeader header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    private static ReadOnlySpan<byte> PayloadSerializer(JwtPayload payload) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);
}
