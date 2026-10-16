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

    /// <summary>
    /// The instant of the clock the rows of the CLR number shapes validate under, 120 seconds after
    /// 1970-01-01T00:00:00Z, so the time claims they carry, 100 to 200 seconds after it, fit in each of the eight
    /// shapes the reader names, a <see cref="byte"/> included.
    /// </summary>
    private static DateTimeOffset ShapeClockInstant { get; } = DateTimeOffset.UnixEpoch.AddSeconds(120);

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


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 Section 6.1</see>: "the JWT Claims Set
    /// MUST contain a cnf claim with a jkt member" whose value "MUST be the base64url encoding (as defined in [RFC7515])
    /// of the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key (in JWK format) to which the access
    /// token is bound." A blank <c>jkt</c> encodes no thumbprint and binds the token to no key a proof could carry. A
    /// signed access token whose <c>cnf</c> carries a blank <c>jkt</c> is refused as
    /// <see cref="JwsAccessTokenValidationFailureReason.Malformed"/> with the description "Access token cnf claim carries
    /// a blank jkt.", and no claims are surfaced. The rows: an empty <c>jkt</c>; a <c>jkt</c> of three spaces.
    /// </summary>
    /// <param name="blankThumbprint">The blank <c>jkt</c> the <c>cnf</c> carries.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("", DisplayName = "an empty jkt")]
    [DataRow("   ", DisplayName = "a jkt of three spaces")]
    public async Task ValidatorRefusesACnfWhoseJktIsBlankAsMalformedAsync(string blankThumbprint)
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
        payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
        {
            [WellKnownJwtClaimNames.JwkThumbprint] = blankThumbprint
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A blank jkt binds the token to no key.");
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
        Assert.AreEqual("Access token cnf claim carries a blank jkt.", result.FailureDescription);
        Assert.IsNull(result.Claims, "A refused token surfaces no claims.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8705#section-3">RFC 8705 Section 3</see>: "The protected resource
    /// MUST obtain, from its TLS implementation layer, the client certificate used for mutual TLS and MUST verify that
    /// the certificate matches the certificate associated with the access token.", a binding the validator cannot verify,
    /// and <see href="https://www.rfc-editor.org/rfc/rfc7800#section-3.1">RFC 7800 Section 3.1</see>: "Specific
    /// applications of JWTs will require implementations to understand and process some confirmation members in particular
    /// ways." A signed access token whose <c>cnf</c> is a well-formed object carrying no <c>jkt</c> is refused with
    /// <see cref="JwsAccessTokenValidationFailureReason.UnsupportedConfirmationMethod"/> and the description "Access token
    /// cnf claim carries no jkt confirmation this validator reads.", and no claims are surfaced: the library's fail-closed
    /// reading, which departs from RFC 7800 Section 3.1's "all confirmation members that are not understood by
    /// implementations MUST be ignored". The rows: a certificate thumbprint <c>x5t#S256</c> alone; a key identifier
    /// <c>kid</c> alone, a member the validator does not understand.
    /// </summary>
    /// <param name="memberName">The one member the <c>cnf</c> carries.</param>
    /// <param name="memberValue">Its value.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("x5t#S256", "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2", DisplayName = "a certificate thumbprint alone")]
    [DataRow("kid", "dfd1aa97-6d8d-4575-a0fe-34b96de2bfad", DisplayName = "a key identifier alone")]
    public async Task ValidatorRefusesACnfWithoutJktAsAnUnsupportedConfirmationMethodAsync(string memberName, string memberValue)
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
        payload[WellKnownJwtClaimNames.Cnf] = new Dictionary<string, object>
        {
            [memberName] = memberValue
        };
        string token = await BuildSignedAccessTokenAsync(keys.PrivateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, keys.PublicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A token constrained by a method the validator cannot enforce is not served unbound.");
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.UnsupportedConfirmationMethod, result.FailureReason);
        Assert.AreEqual("Access token cnf claim carries no jkt confirmation this validator reads.", result.FailureDescription);
        Assert.IsNull(result.Claims, "A refused token surfaces no claims.");
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
    /// An access token whose <c>exp</c>, <c>iat</c> or <c>nbf</c> is no NumericDate naming an instant a
    /// <see cref="DateTimeOffset"/> can hold, a JSON string of digits or the integer 1000000000000000, is refused
    /// as <see cref="JwsAccessTokenValidationFailureReason.Malformed"/> with the description "Access token
    /// &lt;claim&gt; claim is not a NumericDate naming a representable instant.", never read as an absent claim
    /// and never an exception.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</see>, of the
    /// <c>exp</c>, <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">Section 4.1.5</see>, of the
    /// <c>nbf</c>, and <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">Section 4.1.6</see>, of
    /// the <c>iat</c>: "Its value MUST be a number containing a NumericDate value."
    /// </summary>
    /// <param name="claimName">The time claim the value is set on.</param>
    /// <param name="caseName">The value: <c>digitString</c> or <c>tenToTheFifteen</c>.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow("exp", "digitString", DisplayName = "an exp of a string of digits")]
    [DataRow("iat", "digitString", DisplayName = "an iat of a string of digits")]
    [DataRow("nbf", "digitString", DisplayName = "an nbf of a string of digits")]
    [DataRow("iat", "tenToTheFifteen", DisplayName = "an iat of 1e15")]
    public async Task ValidatorRefusesATimeClaimThatIsNoRepresentableNumericDateAsMalformed(string claimName, string caseName)
    {
        object value = caseName switch
        {
            "digitString" => NowInstant.ToUnixTimeSeconds().ToString(System.Globalization.CultureInfo.InvariantCulture),
            "tenToTheFifteen" => 1_000_000_000_000_000L,
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, null)
        };

        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        JwtPayload payload = BuildDefaultPayload();
        payload[claimName] = value;
        string token = await BuildSignedAccessTokenAsync(privateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(token, publicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
        Assert.AreEqual($"Access token {claimName} claim is not a NumericDate naming a representable instant.", result.FailureDescription);
    }


    /// <summary>
    /// An access token whose decoder hands its <c>exp</c>, <c>iat</c> or <c>nbf</c> as a <see cref="float"/> is
    /// refused as <see cref="JwsAccessTokenValidationFailureReason.Malformed"/> with the description "Access token
    /// &lt;claim&gt; claim is not a NumericDate naming a representable instant.", whatever value the
    /// <see cref="float"/> holds: here the claims name 200, 100 and 110 seconds after 1970-01-01T00:00:00Z under a
    /// clock 120 seconds after it, each held exactly. A <see cref="float"/> has 24 mantissa bits and holds only one
    /// epoch second in 128 of this era exactly (between 2^30 and 2^31 seconds its spacing is 128 seconds, so an
    /// instant read from one is off by up to 64 seconds), and refusing the shape as a whole is this library's rule.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 Section 4.1.4</see>, of the
    /// <c>exp</c>, <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">Section 4.1.5</see>, of the
    /// <c>nbf</c>, and <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">Section 4.1.6</see>, of
    /// the <c>iat</c>: "Its value MUST be a number containing a NumericDate value."
    /// </summary>
    /// <param name="claimName">The time claim the parser delegate hands as a <see cref="float"/>.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow("exp", DisplayName = "an exp handed as a float")]
    [DataRow("iat", DisplayName = "an iat handed as a float")]
    [DataRow("nbf", DisplayName = "an nbf handed as a float")]
    public async Task ValidatorRefusesATimeClaimHandedAsAFloatAsMalformed(string claimName)
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Iat] = 100L;
        payload[WellKnownJwtClaimNames.Nbf] = 110L;
        payload[WellKnownJwtClaimNames.Exp] = 200L;
        string token = await BuildSignedAccessTokenAsync(privateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(
            token,
            publicKey,
            parser: ParserHandingTimeClaimsInShape("float", claimName),
            timeProvider: new FakeTimeProvider(ShapeClockInstant)).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.Malformed, result.FailureReason);
        Assert.AreEqual($"Access token {claimName} claim is not a NumericDate naming a representable instant.", result.FailureDescription);
    }


    /// <summary>
    /// An access token whose decoder hands its <c>exp</c>, <c>nbf</c> and <c>iat</c> as a <see cref="long"/>, an
    /// <see cref="int"/>, a <see cref="short"/>, a <see cref="byte"/>, a <see cref="ulong"/>, a <see cref="uint"/>,
    /// a <see cref="double"/> or a <see cref="decimal"/> is valid, and the instants surfaced are the ones the
    /// numbers name, the fraction of a <see cref="double"/> and of a <see cref="decimal"/> kept to the tick. The
    /// parser delegate hands the three claims of the signed token in the row's shape; the clock is 120 seconds after
    /// 1970-01-01T00:00:00Z, and the <c>iat</c>, <c>nbf</c> and <c>exp</c> are 100, 110 and 200 seconds after it
    /// plus the row's fraction, so every shape, a <see cref="byte"/> included, holds them.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 Section 2</see>: "NumericDate A JSON
    /// numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the specified UTC
    /// date/time, ignoring leap seconds. This is equivalent to the IEEE Std 1003.1, 2013 Edition [POSIX.1]
    /// definition "Seconds Since the Epoch", in which each day is accounted for by exactly 86400 seconds, other
    /// than that non-integer values can be represented."
    /// </summary>
    /// <param name="shape">The CLR number shape the parser delegate hands the three claims in.</param>
    /// <param name="fraction">The fraction of a second each claim carries past its whole second, as invariant text.</param>
    /// <param name="fractionTicks">That fraction in ticks.</param>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    [DataRow("long", "0", 0L, DisplayName = "exp, nbf and iat handed as a long")]
    [DataRow("int", "0", 0L, DisplayName = "exp, nbf and iat handed as an int")]
    [DataRow("short", "0", 0L, DisplayName = "exp, nbf and iat handed as a short")]
    [DataRow("byte", "0", 0L, DisplayName = "exp, nbf and iat handed as a byte")]
    [DataRow("ulong", "0", 0L, DisplayName = "exp, nbf and iat handed as a ulong")]
    [DataRow("uint", "0", 0L, DisplayName = "exp, nbf and iat handed as a uint")]
    [DataRow("double", "0.25", 2_500_000L, DisplayName = "exp, nbf and iat handed as a double with a fraction")]
    [DataRow("decimal", "0.1234567", 1_234_567L, DisplayName = "exp, nbf and iat handed as a decimal with a fraction")]
    public async Task ValidatorReadsTheTimeClaimsInEachNumberShapeTheReaderNames(string shape, string fraction, long fractionTicks)
    {
        decimal fractionSeconds = decimal.Parse(fraction, System.Globalization.CultureInfo.InvariantCulture);
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;
        JwtPayload payload = BuildDefaultPayload();
        payload[WellKnownJwtClaimNames.Iat] = 100m + fractionSeconds;
        payload[WellKnownJwtClaimNames.Nbf] = 110m + fractionSeconds;
        payload[WellKnownJwtClaimNames.Exp] = 200m + fractionSeconds;
        string token = await BuildSignedAccessTokenAsync(privateKey, payload).ConfigureAwait(false);

        JwsAccessTokenValidationResult result = await ValidateAsync(
            token,
            publicKey,
            parser: ParserHandingTimeClaimsInShape(shape, WellKnownJwtClaimNames.Exp, WellKnownJwtClaimNames.Nbf, WellKnownJwtClaimNames.Iat),
            timeProvider: new FakeTimeProvider(ShapeClockInstant)).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Validation must succeed; got {result.FailureReason}: {result.FailureDescription}");
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(100).AddTicks(fractionTicks), result.Claims!.IssuedAt);
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(110).AddTicks(fractionTicks), result.Claims.NotBefore);
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(200).AddTicks(fractionTicks), result.Claims.Expiration);
    }


    /// <summary>
    /// A parser delegate over <see cref="JwsAccessTokenTestSupport.Parser"/> that hands the named claims of the
    /// payload in the CLR number shape <paramref name="shape"/> names, each read from its JSON number as a decoder
    /// of that shape reads it; every other member is handed as the test parser reads it.
    /// </summary>
    /// <param name="shape">
    /// The shape: <c>long</c>, <c>int</c>, <c>short</c>, <c>byte</c>, <c>ulong</c>, <c>uint</c>, <c>double</c>,
    /// <c>decimal</c> or <c>float</c>.
    /// </param>
    /// <param name="claimNames">The claims handed in that shape; each is a number in the signed payload.</param>
    /// <returns>The parser.</returns>
    internal static JwsAccessTokenJsonParser ParserHandingTimeClaimsInShape(string shape, params string[] claimNames) => new()
    {
        ParseHeader = JwsAccessTokenTestSupport.Parser.ParseHeader,
        ParseClaims = bytes =>
        {
            JwtPayload payload = JwsAccessTokenTestSupport.Parser.ParseClaims(bytes);
            using JsonDocument document = JsonDocument.Parse(bytes);
            foreach(string claimName in claimNames)
            {
                payload[claimName] = InShape(document.RootElement.GetProperty(claimName), shape);
            }

            return payload;
        }
    };


    /// <summary>
    /// The JSON number <paramref name="number"/> read in the CLR shape <paramref name="shape"/> names, boxed.
    /// </summary>
    /// <param name="number">The JSON number.</param>
    /// <param name="shape">The shape, as <see cref="ParserHandingTimeClaimsInShape"/> names them.</param>
    /// <returns>The number in that shape.</returns>
    private static object InShape(JsonElement number, string shape) => shape switch
    {
        "long" => number.GetInt64(),
        "int" => number.GetInt32(),
        "short" => number.GetInt16(),
        "byte" => number.GetByte(),
        "ulong" => number.GetUInt64(),
        "uint" => number.GetUInt32(),
        "double" => number.GetDouble(),
        "decimal" => number.GetDecimal(),
        "float" => number.GetSingle(),
        _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null)
    };


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


    /// <summary>
    /// Validates <paramref name="token"/> with the verification key resolved for <see cref="DefaultKid"/> as
    /// <paramref name="publicKey"/>.
    /// </summary>
    /// <param name="token">The compact access token.</param>
    /// <param name="publicKey">The verification key the resolver answers for <see cref="DefaultKid"/>.</param>
    /// <param name="expectedAuthorizedParty">The authorized party the validator enforces, or <see langword="null"/> for none.</param>
    /// <param name="parser">The parser delegate, or <see langword="null"/> for <see cref="JwsAccessTokenTestSupport.Parser"/>.</param>
    /// <param name="timeProvider">The clock, or <see langword="null"/> for the class clock at <see cref="NowInstant"/>.</param>
    /// <returns>The validation result.</returns>
    private async Task<JwsAccessTokenValidationResult> ValidateAsync(
        string token,
        PublicKeyMemory publicKey,
        string? expectedAuthorizedParty = null,
        JwsAccessTokenJsonParser? parser = null,
        TimeProvider? timeProvider = null)
    {
        ValueTask<PublicKeyMemory?> resolver(KeyId kid, KeyUsageContext usage, TenantId tenant, ExchangeContext ctx, CancellationToken ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(string.Equals(kid.Value, DefaultKid, StringComparison.Ordinal)
                ? publicKey : null);

        return await ValidateInternalAsync(token, resolver, expectedAuthorizedParty, parser, timeProvider).ConfigureAwait(false);
    }


    /// <summary>
    /// Validates <paramref name="token"/> through <see cref="JwsAccessTokenValidator.ValidateAsync"/> with the
    /// class's issuer, audience and skew.
    /// </summary>
    /// <param name="token">The compact access token.</param>
    /// <param name="resolver">The verification-key resolver.</param>
    /// <param name="expectedAuthorizedParty">The authorized party the validator enforces, or <see langword="null"/> for none.</param>
    /// <param name="parser">The parser delegate, or <see langword="null"/> for <see cref="JwsAccessTokenTestSupport.Parser"/>.</param>
    /// <param name="timeProvider">The clock, or <see langword="null"/> for the class clock at <see cref="NowInstant"/>.</param>
    /// <returns>The validation result.</returns>
    private async Task<JwsAccessTokenValidationResult> ValidateInternalAsync(
        string token,
        ServerVerificationKeyResolverDelegate resolver,
        string? expectedAuthorizedParty = null,
        JwsAccessTokenJsonParser? parser = null,
        TimeProvider? timeProvider = null)
    {
        return await JwsAccessTokenValidator.ValidateAsync(
            token,
            DefaultIssuer,
            DefaultAudience,
            resolver,
            MicrosoftCryptographicFunctionsAdapter.VerifyP256Async,
            parser ?? JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            timeProvider ?? TimeProvider,
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
