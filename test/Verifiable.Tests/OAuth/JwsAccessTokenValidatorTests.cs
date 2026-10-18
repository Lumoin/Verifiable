using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
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

    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch.AddDays(-15);
    private static TimeSpan IatSkew { get; } = TimeSpan.FromSeconds(60);

    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);


    [TestMethod]
    public async Task ValidatorAcceptsWellFormedAccessToken()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

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


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>: "Resource servers
    /// receiving a JWT access token MUST validate it in the following manner" and the signature step it
    /// names; an access token longer than <see cref="Jws.DefaultMaxJwsLength"/>, the longest compact JWS
    /// the library verifies, cannot be validated. <see cref="JwsAccessTokenValidator.ValidateAsync"/>
    /// answers it as <see cref="JwsAccessTokenValidationFailureReason.Malformed"/>, never an exception.
    /// The validator is public and is called directly here;
    /// <see cref="ResourceServerEndToEndTests.AccessTokenLongerThanTheVerifiedMaximumReturns401"/> presents
    /// such a token to a resource server over the wire.
    /// </summary>
    [TestMethod]
    public async Task ValidatorAnswersATokenLongerThanTheVerifiedMaximumAsMalformedAsync()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);
        string oversizedToken = token + new string('A', Jws.DefaultMaxJwsLength);

        JwsAccessTokenValidationResult result = await ValidateAsync(oversizedToken, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
    }


    /// <summary>
    /// Pins that the validator accepts a bare-string <c>aud</c> — RFC 7519 §4.1.3's single-audience
    /// MAY special case — even though this library's own producer
    /// (<see cref="Verifiable.JCose.JwtPayloadExtensions.ForAccessToken"/>) always emits the array
    /// form and so never exercises the bare-string wire shape itself. A conformant foreign producer
    /// that DOES take the MAY special case must still be accepted; the payload here bypasses
    /// <see cref="OAuthAccessTokenFixtures"/> and sets <c>aud</c> to a raw string directly so the
    /// producer-side unification can never narrow what this reader accepts.
    /// </summary>
    [TestMethod]
    public async Task ValidatorAcceptsBareStringAudienceFromAForeignProducer()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
        //Overwrite the fixture's array-shaped aud with the RFC 7519 §4.1.3 bare-string form.
        payload[WellKnownJwtClaimNames.Aud] = DefaultAudience;
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"A bare-string aud must be accepted (RFC 7519 §4.1.3); got {result.FailureReason}: {result.FailureDescription}");
        Assert.HasCount(1, result.Claims!.Audience);
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
        JwtPayload noneAlgPayload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
        string payloadJson = JsonSerializer.Serialize((Dictionary<string, object>)noneAlgPayload);
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
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        //Resolver returns null for any kid — simulating an unknown key.
        static ValueTask<PublicKeyMemory?> resolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(null);

        JwsAccessTokenValidationResult result = await ValidateInternalAsync(token, resolver).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.UnknownKid, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsTamperedSignature()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        //Flip a middle character of the signature segment so it still
        //base64url-decodes but verifies as false.
        int signatureStart = token.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((token.Length - signatureStart) / 2);
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
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: "https://other-issuer.test/tenant-b",
            audience: [DefaultAudience]);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.IssuerMismatch, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsAudienceMismatch()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: ["other-resource-server"]);
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
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: auds);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.HasCount(3, result.Claims!.Audience);
    }


    [TestMethod]
    public async Task ValidatorRejectsExpiredToken()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromHours(2),
            expiresAt: NowInstant - TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Expired, result.FailureReason);
    }


    [TestMethod]
    public async Task ValidatorRejectsTokenIssuedInFuture()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant + TimeSpan.FromHours(2),
            expiresAt: NowInstant + TimeSpan.FromHours(3),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
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

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
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
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
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
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: auds);
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
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: auds);
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
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: auds);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        //No expected authorized party supplied: azp is not enforced even with multiple audiences.
        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
    }


    [TestMethod]
    public async Task ValidatorRejectsExpiryAtOrBeforeIssuance()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant + TimeSpan.FromMinutes(2),
            expiresAt: NowInstant + TimeSpan.FromMinutes(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
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
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromSeconds(30),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);
        payload[WellKnownJwtClaimNames.Nbf] = (NowInstant + TimeSpan.FromSeconds(60)).ToUnixTimeSeconds();
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.InconsistentTemporalClaims, result.FailureReason,
            "exp at or before nbf means the validity window never opens and must be rejected.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> Figure 5,
    /// the single-actor shape: "The 'act' claim value is a JSON object, and members in the JSON
    /// object are claims that identify the actor." A token carrying <c>act = { "sub": ... }</c>
    /// surfaces that party as the current actor, with an empty delegation history — one hop happened.
    /// </summary>
    [TestMethod]
    public async Task ValidatorSurfacesTheCurrentActorFromASingleActClaim()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        //RFC 8693 §4.1 Figure 5's act object, transcribed.
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = "admin@example.com"
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.IsNotNull(result.Claims!.Act);
        CurrentActor actor = result.Claims.Act!;
        Assert.AreEqual("admin@example.com", actor.Subject);
        Assert.IsNull(actor.Issuer, "Figure 5's act names no issuer.");
        Assert.IsEmpty(actor.DelegationHistory, "A single actor has no prior actors.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: "The
    /// outermost 'act' claim represents the current actor while nested 'act' claims represent prior
    /// actors. The least recent actor is the most deeply nested." A three-link chain therefore
    /// surfaces the outermost party as the current actor and orders the history from most recent
    /// prior to least recent — the deepest link last.
    /// </summary>
    [TestMethod]
    public async Task ValidatorOrdersDelegationHistoryWithTheLeastRecentActorLast()
    {
        const string CurrentActorSubject = "https://service16.example.com";
        const string MostRecentPrior = "https://service77.example.com";
        const string LeastRecentPrior = "https://service01.example.com";

        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = CurrentActorSubject,
            [WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.Sub] = MostRecentPrior,
                [WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [WellKnownJwtClaimNames.Sub] = LeastRecentPrior
                }
            }
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        CurrentActor actor = result.Claims!.Act!;
        Assert.AreEqual(CurrentActorSubject, actor.Subject, "The outermost act is the current actor.");
        Assert.HasCount(2, actor.DelegationHistory);
        Assert.AreEqual(MostRecentPrior, actor.DelegationHistory[0].Subject,
            "The actor nested immediately inside the current one is the most recent prior actor.");
        Assert.AreEqual(LeastRecentPrior, actor.DelegationHistory[^1].Subject,
            "The most deeply nested actor is the least recent and is therefore last.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> binds the
    /// consumer: "For the purpose of applying access control policy, the consumer of a token MUST
    /// only consider the token's top-level claims and the party identified as the current actor by
    /// the 'act' claim. Prior actors identified by any nested 'act' claims are informational only
    /// and are not to be considered in access control decisions." The type surface says the same
    /// thing structurally — the decision input is
    /// <see cref="CurrentActor.Subject"/>/<see cref="CurrentActor.Issuer"/>, while
    /// <see cref="CurrentActor.DelegationHistory"/> is a read-only list of
    /// <see cref="PriorActor"/> that carries identity members only and offers no further chain to
    /// walk. Here the privileged party appears ONLY in that history, and the §4.1-conformant
    /// decision denies while the history still records it for audit.
    /// </summary>
    [TestMethod]
    public async Task PriorActorsAreHistoryAndNeverAuthorizeTheRequest()
    {
        const string PrivilegedParty = "https://svc.example/privileged";
        const string CurrentActorSubject = "https://svc.example/unprivileged";

        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = CurrentActorSubject,
            [WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwtClaimNames.Sub] = PrivilegedParty
            }
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        CurrentActor actor = result.Claims!.Act!;

        //The §4.1-conformant resource-server decision: top-level claims plus the current actor only.
        static bool IsPermitted(JwsAccessTokenClaims claims, string allowedActor) =>
            claims.Act is null || string.Equals(claims.Act.Subject, allowedActor, StringComparison.Ordinal);

        Assert.IsFalse(IsPermitted(result.Claims!, PrivilegedParty),
            "The privileged party is a prior actor only, so a §4.1-conformant decision must not permit the request.");

        //The history is offered as read-only audit evidence, not as an authorization input: it is an
        //IReadOnlyList of identity-only prior actors with no nested chain to descend into.
        IReadOnlyList<PriorActor> history = actor.DelegationHistory;
        Assert.HasCount(1, history);
        Assert.AreEqual(PrivilegedParty, history[0].Subject,
            "The prior actor stays visible as history — informational, never authority.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: "claims
    /// within the 'act' claim pertain only to the identity of the actor and are not relevant to the
    /// validity of the containing JWT in the same manner as the top-level claims. Consequently,
    /// non-identity claims (e.g., 'exp', 'nbf', and 'aud') are not meaningful when used within an
    /// 'act' claim and are therefore not used." An actor carrying a long-expired <c>exp</c> and a
    /// foreign <c>aud</c> therefore neither invalidates the token nor changes what it validates
    /// against.
    /// </summary>
    [TestMethod]
    public async Task NonIdentityMembersInsideActAreNotValidityInputs()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = "https://svc.example/agent",
            [WellKnownJwtClaimNames.Exp] = (NowInstant - TimeSpan.FromDays(365)).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Nbf] = (NowInstant + TimeSpan.FromDays(365)).ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Aud] = "https://some-other-resource.test"
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess,
            $"Non-identity members inside act must not affect the containing token's validity; got {result.FailureReason}: {result.FailureDescription}");
        Assert.AreEqual("https://svc.example/agent", result.Claims!.Act!.Subject);
        Assert.HasCount(1, result.Claims.Audience);
        Assert.AreEqual(DefaultAudience, result.Claims.Audience[0],
            "The token's own aud is the validity input; the actor's is not.");
    }


    /// <summary>
    /// The declined half at the resource: a token that records no delegation carries no <c>act</c>
    /// claim, so no current actor is surfaced. ID-JAG §3.1 and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-1.1">RFC 8693 §1.1</see> both leave
    /// composite-token issuance discretionary ("When and if a composite token is issued is at the
    /// discretion of the authorization server"), so the absence is an ordinary, valid shape and not
    /// a failure.
    /// </summary>
    [TestMethod]
    public async Task ValidatorSurfacesNoActorForAnUndelegatedToken()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, BuildDefaultPayload()).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.IsNull(result.Claims!.Act);
        Assert.IsNull(result.Claims.MayActSubject);
        Assert.IsNull(result.Claims.MayActIssuer);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: "The
    /// 'act' claim value is a JSON object." A token whose <c>act</c> is a bare string asserts a
    /// delegation the resource server cannot read; it is rejected rather than reported as a token
    /// with no delegation at all, since the permissive reading is the one an attacker would want.
    /// </summary>
    [TestMethod]
    public async Task ValidatorRejectsActClaimThatIsNotAnObject()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Act] = "https://svc.example/agent";
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
    }


    /// <summary>
    /// The members of an <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693
    /// §4.1</see> <c>act</c> object "are claims that identify the actor". An object naming no
    /// <c>sub</c> identifies nobody, so there is no current actor for the consumer to consider and
    /// the token is rejected.
    /// </summary>
    [TestMethod]
    public async Task ValidatorRejectsActClaimNamingNoSubject()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Iss] = DefaultIssuer
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see>: the
    /// nested claims "serve as a history trail that connects the initial request and subject through
    /// the various delegation steps undertaken before reaching the current actor". A nested link
    /// naming no party breaks that trail, so the token is rejected rather than surfacing a chain
    /// truncated at the last readable level.
    /// </summary>
    [TestMethod]
    public async Task ValidatorRejectsNestedActClaimNamingNoSubject()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = "https://svc.example/agent",
            [WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
    }


    /// <summary>
    /// An actor identity member that is not a non-empty string identifies no party — the
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.1">RFC 8693 §4.1</see> members
    /// "identify the actor", and a number is not an identifier a resource server can make an access
    /// control decision against.
    /// </summary>
    [TestMethod]
    public async Task ValidatorRejectsActClaimWithNonStringSubject()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Act] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = 4711L
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: the
    /// <c>may_act</c> claim "makes a statement that one party is authorized to become the actor and
    /// act on behalf of another party", and "the combination of the two claims 'iss' and 'sub' are
    /// sometimes necessary to uniquely identify an authorized actor" — both members are surfaced to
    /// the resource server.
    /// </summary>
    [TestMethod]
    public async Task ValidatorSurfacesMayActSubjectAndIssuer()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.MayAct] = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwtClaimNames.Sub] = "admin@example.com",
            [WellKnownJwtClaimNames.Iss] = DefaultIssuer
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.AreEqual("admin@example.com", result.Claims!.MayActSubject);
        Assert.AreEqual(DefaultIssuer, result.Claims.MayActIssuer);
    }


    /// <summary>
    /// A <c>may_act</c> object naming neither a <c>sub</c> nor an <c>iss</c> identifies no party.
    /// Reducing that unreadable statement to "no constraint" would erase the restriction
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see> exists to
    /// express, so the token is rejected instead.
    /// </summary>
    [TestMethod]
    public async Task ValidatorRejectsMayActNamingNoParty()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.MayAct] = new Dictionary<string, object>(StringComparer.Ordinal);
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.4">RFC 8693 §4.4</see>: "The
    /// claim value is a JSON object." A bare-string <c>may_act</c> is not that object and is
    /// rejected rather than silently ignored.
    /// </summary>
    [TestMethod]
    public async Task ValidatorRejectsMayActThatIsNotAnObject()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.MayAct] = "admin@example.com";
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
    }


    /// <summary>
    /// A token whose parts are written by hand and signed over their exact bytes is read through the library's own readings
    /// (<see cref="JwsAccessTokenJsonParser.Default"/>) and validates: its array <c>aud</c>, its fractional <c>iat</c>, its
    /// <c>cnf</c> (RFC 7800 section 3) and its nested <c>act</c> chain (RFC 8693 section 4.1) read back as the claims it
    /// answers.
    /// </summary>
    [TestMethod]
    public async Task ValidatorReadsAHandWrittenTokenThroughTheLibrarysReadingAndAcceptsIt()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var token = await SignRawAsync(keys.PrivateKey, RawHeaderJson, RawPayloadJson(string.Empty, string.Empty)).ConfigureAwait(false);

        var result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.AreEqual(DefaultSubject, result.Claims!.Subject);
        Assert.AreSequenceEqual(new[] { DefaultAudience, "another-resource" }, result.Claims.Audience);
        Assert.AreEqual(RawIssuedAt, result.Claims.IssuedAt.ToString());
        Assert.AreEqual("bound-key-thumbprint", result.Claims.Confirmation!.JwkThumbprint);
        Assert.AreEqual("agent", result.Claims.Act!.Subject);
        Assert.AreEqual("earlier-agent", result.Claims.Act.DelegationHistory[0].Subject);
    }


    /// <summary>
    /// A part the library's reading refuses, or a claims set missing or misshaping a claim the validator requires, is refused
    /// with its typed reason, on a token otherwise valid and signed over its exact bytes: a header repeating a member names no
    /// <c>alg</c> one way and is an invalid header; a claims set repeating a claim (RFC 8259 section 4) or holding one naming no
    /// Unicode text (RFC 8259 section 8.2) is malformed; an <c>exp</c> that is no NumericDate (RFC 7519 section 2) is malformed,
    /// never read as absent; and a claims set omitting the <c>sub</c> RFC 9068 section 2.2 requires is missing a required claim.
    /// </summary>
    /// <param name="headerMember">A member appended to the header, as JSON text after a comma, or empty.</param>
    /// <param name="omittedClaim">The claim the claims set leaves out, or empty.</param>
    /// <param name="payloadMember">A member appended to the claims set, as JSON text after a comma, or empty.</param>
    /// <param name="expected">The reason the refusal names.</param>
    [TestMethod]
    [DataRow(",\"alg\":\"ES256\"", "", "", JwsAccessTokenValidationFailureReason.InvalidHeader, DisplayName = "A header repeating alg")]
    [DataRow("", "", ",\"scope\":\"more\"", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "A claims set repeating scope")]
    [DataRow("", "", ",\"note\":\"\\uD800\"", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "A claim naming no Unicode text")]
    [DataRow("", "exp", ",\"exp\":\"1900000000\"", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "An exp of digits in a string")]
    [DataRow("", "exp", ",\"exp\":1e400", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "An exp naming no instant a clock represents")]
    [DataRow("", "sub", "", JwsAccessTokenValidationFailureReason.MissingRequiredClaim, DisplayName = "A claims set omitting sub")]
    public async Task ValidatorRefusesWhatTheReadingOrTheClaimsRefuseByItsReason(
        string headerMember,
        string omittedClaim,
        string payloadMember,
        JwsAccessTokenValidationFailureReason expected)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var header = string.Concat(RawHeaderJson.AsSpan(0, RawHeaderJson.Length - 1), headerMember, "}");
        var token = await SignRawAsync(keys.PrivateKey, header, RawPayloadJson(omittedClaim, payloadMember)).ConfigureAwait(false);

        var result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(expected, result.FailureReason, result.FailureDescription);
    }


    /// <summary>
    /// The reading's refusal of a token's part is carried into the validation result whole, with the segment it concerns, beside
    /// the coarse category: a header repeating <c>alg</c> as the JSON reader's refusal of the protected header, a claims set
    /// repeating <c>scope</c> or holding a claim naming no Unicode text as its refusal of the payload; a failure no reading
    /// refused - an <c>exp</c> of digits in a string - carries none.
    /// </summary>
    /// <returns>A task completing once the tokens are judged.</returns>
    [TestMethod]
    public async Task ValidatorCarriesTheReadingsRefusalWithTheSegmentItConcerns()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var repeatedAlgHeader = string.Concat(RawHeaderJson.AsSpan(0, RawHeaderJson.Length - 1), ",\"alg\":\"ES256\"}");

        var header = await ValidateAsync(await SignRawAsync(keys.PrivateKey, repeatedAlgHeader, RawPayloadJson(string.Empty, string.Empty)).ConfigureAwait(false), keys.PublicKey).ConfigureAwait(false);
        var repeated = await ValidateAsync(await SignRawAsync(keys.PrivateKey, RawHeaderJson, RawPayloadJson(string.Empty, ",\"scope\":\"more\"")).ConfigureAwait(false), keys.PublicKey).ConfigureAwait(false);
        var undecodable = await ValidateAsync(await SignRawAsync(keys.PrivateKey, RawHeaderJson, RawPayloadJson(string.Empty, ",\"note\":\"\\uD800\"")).ConfigureAwait(false), keys.PublicKey).ConfigureAwait(false);
        var unread = await ValidateAsync(await SignRawAsync(keys.PrivateKey, RawHeaderJson, RawPayloadJson("exp", ",\"exp\":\"1900000000\"")).ConfigureAwait(false), keys.PublicKey).ConfigureAwait(false);

        Assert.AreEqual(JwsAccessTokenValidationFailureReason.InvalidHeader, header.FailureReason);
        Assert.AreEqual(JwsPart.ProtectedHeader, header.PartRefusal?.Part);
        Assert.AreEqual(WellKnownJoseHeaderNames.Alg, ((header.PartRefusal as JwsPartDocumentRefusal)?.Refusal as JsonRepeatedMemberName)?.Name);

        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, repeated.FailureReason);
        Assert.AreEqual(JwsPart.Payload, repeated.PartRefusal?.Part);
        Assert.AreEqual(WellKnownJwtClaimNames.Scope, ((repeated.PartRefusal as JwsPartDocumentRefusal)?.Refusal as JsonRepeatedMemberName)?.Name);

        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, undecodable.FailureReason);
        _ = Assert.IsInstanceOfType<JsonUndecodableMember>((undecodable.PartRefusal as JwsPartDocumentRefusal)?.Refusal);

        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, unread.FailureReason);
        Assert.IsNull(unread.PartRefusal, "A failure no reading refused carries no reading's refusal.");
    }


    /// <summary>
    /// RFC 7519 section 4.1.3: <c>aud</c> is one StringOrURI or an array of them. A token whose <c>aud</c> array holds the expected
    /// audience beside an element that is no non-empty string - <c>null</c>, a number, an empty string - is refused as malformed
    /// as a whole, never filtered into the audience it does name; an empty array, an empty string and a value of another kind are
    /// malformed too, told from an omitted <c>aud</c>, which is a missing required claim; the expected audience alone, as a string
    /// or a one-element array, validates.
    /// </summary>
    /// <param name="audienceJson">The <c>aud</c>'s JSON text, or empty to omit it.</param>
    /// <param name="expected">The reason the token is refused with, or <see langword="null"/> for a valid token.</param>
    /// <returns>A task completing once the token is judged.</returns>
    [TestMethod]
    [DataRow($"[\"{DefaultAudience}\",null]", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "An array holding null")]
    [DataRow($"[\"{DefaultAudience}\",123]", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "An array holding a number")]
    [DataRow($"[\"{DefaultAudience}\",\"\"]", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "An array holding an empty string")]
    [DataRow("[]", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "An empty array")]
    [DataRow("\"\"", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "An empty string")]
    [DataRow("7", JwsAccessTokenValidationFailureReason.Malformed, DisplayName = "A number")]
    [DataRow("", JwsAccessTokenValidationFailureReason.MissingRequiredClaim, DisplayName = "An omitted aud")]
    [DataRow($"[\"{DefaultAudience}\"]", null, DisplayName = "The expected audience in an array")]
    [DataRow($"\"{DefaultAudience}\"", null, DisplayName = "The expected audience as a string")]
    public async Task AMalformedAudienceIsRefusedWholeAndToldFromAnOmittedOne(string audienceJson, JwsAccessTokenValidationFailureReason? expected)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var token = await SignRawAsync(keys.PrivateKey, RawHeaderJson, RawClaimsJson(audienceJson, DefaultConfirmationJson)).ConfigureAwait(false);

        var result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.AreEqual(expected, result.FailureReason, $"{audienceJson}: {result.FailureDescription}");
    }


    /// <summary>
    /// RFC 7800 section 3: a <c>cnf</c> names the key a token is bound to. One that is no JSON object, <c>null</c> among them, one
    /// carrying no member, and one carrying the <c>jkt</c> of RFC 9449 section 6.1 as no non-empty string are refused as malformed,
    /// never read as an unbound token; one carrying a confirmation method this library does not verify possession under - the
    /// <c>x5t#S256</c> of RFC 8705 section 3.1, alone or beside a <c>jkt</c> - is refused as such, never read as unbound nor as
    /// bound by the <c>jkt</c> alone; an omitted <c>cnf</c> validates as unbound and a <c>jkt</c> as bound to it.
    /// </summary>
    /// <param name="confirmationJson">The <c>cnf</c>'s JSON text, or empty to omit it.</param>
    /// <param name="expected">The reason the token is refused with, or <see langword="null"/> for a valid token.</param>
    /// <param name="boundThumbprint">The thumbprint a valid token is bound to, or <see langword="null"/> for an unbound one.</param>
    /// <returns>A task completing once the token is judged.</returns>
    [TestMethod]
    [DataRow("null", JwsAccessTokenValidationFailureReason.Malformed, null, DisplayName = "A null cnf")]
    [DataRow("\"bound-key-thumbprint\"", JwsAccessTokenValidationFailureReason.Malformed, null, DisplayName = "A cnf that is a string")]
    [DataRow("{}", JwsAccessTokenValidationFailureReason.Malformed, null, DisplayName = "A cnf carrying no method")]
    [DataRow(/*lang=json,strict*/ "{\"jkt\":5}", JwsAccessTokenValidationFailureReason.Malformed, null, DisplayName = "A jkt that is a number")]
    [DataRow(/*lang=json,strict*/ "{\"jkt\":\"\"}", JwsAccessTokenValidationFailureReason.Malformed, null, DisplayName = "A jkt that is empty")]
    [DataRow(/*lang=json,strict*/ "{\"x5t#S256\":\"certificate-thumbprint\"}", JwsAccessTokenValidationFailureReason.UnsupportedConfirmationMethod, null, DisplayName = "A certificate-bound cnf")]
    [DataRow(/*lang=json,strict*/ "{\"jkt\":\"bound-key-thumbprint\",\"x5t#S256\":\"certificate-thumbprint\"}", JwsAccessTokenValidationFailureReason.UnsupportedConfirmationMethod, null, DisplayName = "A jkt beside an unverified method")]
    [DataRow("", null, null, DisplayName = "An omitted cnf")]
    [DataRow(/*lang=json,strict*/ "{\"jkt\":\"bound-key-thumbprint\"}", null, "bound-key-thumbprint", DisplayName = "A jkt")]
    public async Task AMalformedConfirmationIsNeverReadAsAnUnboundToken(
        string confirmationJson, JwsAccessTokenValidationFailureReason? expected, string? boundThumbprint)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        var token = await SignRawAsync(keys.PrivateKey, RawHeaderJson, RawClaimsJson(DefaultAudienceJson, confirmationJson)).ConfigureAwait(false);

        var result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.AreEqual(expected, result.FailureReason, $"{confirmationJson}: {result.FailureDescription}");
        Assert.AreEqual(boundThumbprint, result.Claims?.Confirmation?.JwkThumbprint, confirmationJson);
    }


    /// <summary>The <c>aud</c> of a hand-written access token: this suite's audience beside another resource.</summary>
    private const string DefaultAudienceJson = $"[\"{DefaultAudience}\",\"another-resource\"]";

    /// <summary>The <c>cnf</c> of a hand-written access token: a DPoP key thumbprint (RFC 9449 section 6.1).</summary>
    private const string DefaultConfirmationJson = /*lang=json,strict*/ "{\"jkt\":\"bound-key-thumbprint\"}";


    /// <summary>The header of a hand-written access token: ES256 under this suite's key identifier, typed <c>at+jwt</c> (RFC 9068 section 2.1).</summary>
    private static string RawHeaderJson => "{\"alg\":\"ES256\",\"kid\":\"" + DefaultKid + "\",\"typ\":\"at+jwt\"}";

    /// <summary>The hand-written token's <c>iat</c>, a NumericDate with a fraction, one minute before the clock.</summary>
    private static string RawIssuedAt => (NowInstant - TimeSpan.FromMinutes(1)).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture) + ".25";

    /// <summary>The hand-written token's <c>exp</c>, an hour after the clock.</summary>
    private static string RawExpiry => (NowInstant + TimeSpan.FromHours(1)).ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture);


    /// <summary>
    /// The claims set of a hand-written access token valid for this suite, with one claim left out and a member appended as
    /// written.
    /// </summary>
    /// <param name="omitted">The claim left out, <c>sub</c> or <c>exp</c>, or empty for none.</param>
    /// <param name="appended">JSON text appended after the last claim, beginning with its comma, or empty.</param>
    /// <returns>The claims set's JSON text.</returns>
    private static string RawPayloadJson(string omitted, string appended) =>
        "{\"iss\":\"" + DefaultIssuer + "\","
        + (WellKnownJwtClaimNames.IsSub(omitted) ? string.Empty : "\"sub\":\"" + DefaultSubject + "\",")
        + "\"aud\":" + DefaultAudienceJson + ","
        + (WellKnownJwtClaimNames.IsExp(omitted) ? string.Empty : "\"exp\":" + RawExpiry + ",")
        + "\"iat\":" + RawIssuedAt + ",\"client_id\":\"" + DefaultClientId + "\",\"scope\":\"" + DefaultScope + "\","
        + "\"jti\":\"token-1\",\"cnf\":" + DefaultConfirmationJson + ",\"act\":{\"sub\":\"agent\",\"act\":{\"sub\":\"earlier-agent\"}}"
        + appended + "}";


    /// <summary>
    /// The claims set of a hand-written access token valid for this suite but for its <c>aud</c> and <c>cnf</c>, each written as
    /// given and omitted where empty.
    /// </summary>
    /// <param name="audienceJson">The <c>aud</c>'s JSON text, or empty to omit it.</param>
    /// <param name="confirmationJson">The <c>cnf</c>'s JSON text, or empty to omit it.</param>
    /// <returns>The claims set's JSON text.</returns>
    private static string RawClaimsJson(string audienceJson, string confirmationJson) =>
        "{\"iss\":\"" + DefaultIssuer + "\",\"sub\":\"" + DefaultSubject + "\","
        + (audienceJson.Length == 0 ? string.Empty : "\"aud\":" + audienceJson + ",")
        + "\"exp\":" + RawExpiry + ",\"iat\":" + RawIssuedAt + ",\"jti\":\"token-1\""
        + (confirmationJson.Length == 0 ? string.Empty : ",\"cnf\":" + confirmationJson)
        + "}";


    /// <summary>Signs a hand-written header and claims set over their exact UTF-8 bytes, never through a serializer.</summary>
    /// <param name="privateKey">The signing key.</param>
    /// <param name="headerJson">The header's JSON text.</param>
    /// <param name="payloadJson">The claims set's JSON text.</param>
    /// <returns>The compact token.</returns>
    private async Task<string> SignRawAsync(PrivateKeyMemory privateKey, string headerJson, string payloadJson)
    {
        var headerSegment = TestSetup.Base64UrlEncoder(System.Text.Encoding.UTF8.GetBytes(headerJson));
        var payloadSegment = TestSetup.Base64UrlEncoder(System.Text.Encoding.UTF8.GetBytes(payloadJson));

        using var signature = await privateKey.SignAsync(
            System.Text.Encoding.ASCII.GetBytes($"{headerSegment}.{payloadSegment}"), BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        return $"{headerSegment}.{payloadSegment}.{TestSetup.Base64UrlEncoder(signature.AsReadOnlySpan())}";
    }


    /// <summary>
    /// The fixture's baseline RFC 9068 access-token payload — valid <c>iss</c>/<c>aud</c>/timing for
    /// this suite's trust anchor — that the <c>act</c>/<c>may_act</c> tests overlay their claim under
    /// test onto.
    /// </summary>
    /// <returns>The payload.</returns>
    private static JwtPayload BuildDefaultPayload() =>
        OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: DefaultSubject,
            scope: DefaultScope,
            clientId: DefaultClientId,
            issuedAt: NowInstant - TimeSpan.FromMinutes(1),
            expiresAt: NowInstant + TimeSpan.FromHours(1),
            issuer: DefaultIssuer,
            audience: [DefaultAudience]);


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
        ValueTask<PublicKeyMemory?> resolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) =>
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
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            tenantId: default,
            [],
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
