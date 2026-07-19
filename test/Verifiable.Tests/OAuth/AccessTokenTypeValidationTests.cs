using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 9068 §4 <c>typ</c> discriminator — the fix that closes a token-confusion gap where a JWT
/// minted for a different purpose (most concretely, an OIDC ID Token, <c>typ</c> <c>JWT</c>) could be
/// presented at a resource endpoint as if it were an access token. Both independent inbound
/// validation paths carry the check: <see cref="JwsAccessTokenValidator"/> (used directly, e.g. by a
/// resource server composing its own pipeline) and <see cref="BearerTokenValidation"/> (the AS's own
/// protected-resource gate, exercised here through the real OIDC Core §5.3 UserInfo endpoint). Every
/// confused token in this suite is minted by the REAL production issuance pipeline — a full
/// PAR → Authorize → Token exchange — never a hand-literal fixture, so the assertions prove the
/// running system rejects the confusion, not merely that the check exists in isolation.
/// </summary>
[TestClass]
internal sealed class AccessTokenTypeValidationTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string ClientId = "https://typ-confusion.client.test";
    private const string SubjectId = "subject-typ-confusion";
    private const string ResourceServerAudience = "https://rs.example.com";

    private static readonly Uri ClientBaseUri = new(ClientId);
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");
    private static readonly TimeSpan IatSkew = TimeSpan.FromSeconds(60);

    //Standalone (non-host) fixture constants for the hand-built-header tests, mirroring
    //JwsAccessTokenValidatorTests' local fixture shape.
    private const string StandaloneIssuer = "https://issuer.test/tenant-a";
    private const string StandaloneAudience = "test-resource-server";
    private const string StandaloneSubject = "user-1";
    private const string StandaloneClientId = "client-1";
    private const string StandaloneKid = "test-kid";
    private const string StandaloneScope = "openid profile";

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);


    /// <summary>
    /// The genuine access token from a real issuance (typ <c>at+jwt</c>) validates; the SAME
    /// issuance's id_token (typ <c>JWT</c>) — minted by the real OIDC ID Token producer, not a
    /// fixture — must not validate as an access token.
    /// </summary>
    [TestMethod]
    public async Task JwsAccessTokenValidatorRejectsRealIdTokenButAcceptsRealAccessToken()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (string accessToken, string idToken) = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        JwsAccessTokenValidationResult accessResult = await ValidateAsAccessTokenAsync(
            accessToken, material, ResourceServerAudience).ConfigureAwait(false);
        Assert.IsTrue(accessResult.IsSuccess,
            $"A genuine at+jwt access token must validate; got {accessResult.FailureReason}: {accessResult.FailureDescription}");

        JwsAccessTokenValidationResult idTokenResult = await ValidateAsAccessTokenAsync(
            idToken, material, ClientId).ConfigureAwait(false);
        Assert.IsFalse(idTokenResult.IsSuccess,
            "An ID Token (typ JWT) presented to the access-token validator must not succeed.");
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.InvalidType, idTokenResult.FailureReason,
            "The rejection must be attributed to the typ discriminator (RFC 9068 §4), not some other check.");
    }


    /// <summary>A header with no <c>typ</c> member at all is rejected the same as a wrong one.</summary>
    [TestMethod]
    public async Task JwsAccessTokenValidatorRejectsAccessTokenMissingTypHeader()
    {
        string headerJson = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["alg"] = "ES256",
            ["kid"] = StandaloneKid
            //typ deliberately omitted.
        });
        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: StandaloneSubject,
            scope: StandaloneScope,
            clientId: StandaloneClientId,
            issuedAt: TimeProvider.GetUtcNow() - TimeSpan.FromMinutes(1),
            expiresAt: TimeProvider.GetUtcNow() + TimeSpan.FromHours(1),
            issuer: StandaloneIssuer,
            audience: [StandaloneAudience]);
        string payloadJson = JsonSerializer.Serialize((Dictionary<string, object>)payload);
        string token = string.Concat(
            TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(headerJson)),
            ".",
            TestSetup.Base64UrlEncoder(Encoding.UTF8.GetBytes(payloadJson)),
            ".",
            TestSetup.Base64UrlEncoder([0x00]));

        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        JwsAccessTokenValidationResult result = await ValidateStandaloneAsync(token, publicKey).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.InvalidType, result.FailureReason);
    }


    /// <summary>
    /// RFC 9068 §4 accepts EITHER <c>at+jwt</c> or the long-form <c>application/at+jwt</c> — the
    /// producer only ever emits the short form, so this proves the validator's inbound tolerance for
    /// the long form independently, by hand-constructing the header.
    /// </summary>
    [TestMethod]
    public async Task JwsAccessTokenValidatorAcceptsApplicationAtJwtLongForm()
    {
        var keys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory publicKey = keys.PublicKey;
        using PrivateKeyMemory privateKey = keys.PrivateKey;

        JwtHeader header = JwtHeader.ForAccessToken(WellKnownJwaValues.Es256, StandaloneKid);
        header[WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Application.AtJwt;

        JwtPayload payload = OAuthAccessTokenFixtures.BuildAccessTokenPayload(
            subject: StandaloneSubject,
            scope: StandaloneScope,
            clientId: StandaloneClientId,
            issuedAt: TimeProvider.GetUtcNow() - TimeSpan.FromMinutes(1),
            expiresAt: TimeProvider.GetUtcNow() + TimeSpan.FromHours(1),
            issuer: StandaloneIssuer,
            audience: [StandaloneAudience]);

        UnsignedJwt unsignedJwt = new(header, payload);
        using JwsMessage jws = await unsignedJwt.SignAsync(
            privateKey,
            HeaderSerializer,
            PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        string token = JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);

        JwsAccessTokenValidationResult result = await ValidateStandaloneAsync(token, publicKey).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess,
            $"typ 'application/at+jwt' (the long form) must be accepted per RFC 9068 §4; got {result.FailureReason}: {result.FailureDescription}");
    }


    /// <summary>
    /// <see cref="BearerTokenValidation"/> is a structurally independent implementation (its own
    /// parse/alg/kid/typ/key-resolve/signature/iss/exp sequence, not a delegation to
    /// <see cref="JwsAccessTokenValidator"/>) that gates every protected resource endpoint — exercised
    /// here through the real, HTTP-reachable OIDC Core §5.3 UserInfo endpoint. The genuine access
    /// token from a real issuance succeeds; the SAME issuance's id_token is rejected by BearerTokenValidation's
    /// own <c>typ</c> check before ever reaching key resolution or signature verification.
    /// </summary>
    [TestMethod]
    public async Task BearerTokenValidationRejectsRealIdTokenButAcceptsRealAccessToken()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (string accessToken, string idToken) = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        ServerHttpResponse accessResponse = await DispatchUserInfoAsync(
            host, material, "Bearer " + accessToken).ConfigureAwait(false);
        Assert.AreEqual(200, accessResponse.StatusCode,
            $"A genuine at+jwt access token must be accepted at the protected endpoint. Body: {accessResponse.Body}");

        ServerHttpResponse idTokenResponse = await DispatchUserInfoAsync(
            host, material, "Bearer " + idToken).ConfigureAwait(false);
        Assert.AreEqual(401, idTokenResponse.StatusCode,
            $"An ID Token (typ JWT) presented as a Bearer access token must be rejected. Body: {idTokenResponse.Body}");
        Assert.Contains(OAuthErrors.InvalidToken, idTokenResponse.Body, StringComparison.Ordinal);
        Assert.Contains("typ", idTokenResponse.Body, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// The reverse substitution: <see cref="Oidc10IdTokenValidator"/> (RFC 8725 §3.11 explicit typing)
    /// must REFUSE a genuine <c>at+jwt</c> access token — accepting one as an ID Token would trust it as
    /// proof of end-user authentication it never carried — while still accepting the real id_token
    /// (typ <c>JWT</c>) from the same issuance.
    /// </summary>
    [TestMethod]
    public async Task Oidc10IdTokenValidatorRejectsRealAccessTokenButAcceptsRealIdToken()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        (string accessToken, string idToken) = await DriveCodeExchangeAsync(
            host, material, WellKnownScopes.OpenId).ConfigureAwait(false);

        Oidc10IdTokenValidationResult accessAsIdResult = await ValidateAsIdTokenAsync(
            accessToken, material, ClientId).ConfigureAwait(false);
        Assert.IsFalse(accessAsIdResult.IsSuccess,
            "A genuine at+jwt access token must not validate as an ID Token (RFC 8725 §3.11 explicit typing).");
        Assert.AreEqual(JwsAccessTokenValidationFailureReason.InvalidType, accessAsIdResult.FailureReason,
            "The rejection must be attributed to the access-token typ discriminator, not some other check.");

        Oidc10IdTokenValidationResult idTokenResult = await ValidateAsIdTokenAsync(
            idToken, material, ClientId).ConfigureAwait(false);
        Assert.IsTrue(idTokenResult.IsSuccess,
            $"The real id_token (typ JWT) must validate through the ID Token validator; got {idTokenResult.FailureReason}: {idTokenResult.FailureDescription}");
    }


    /// <summary>
    /// Drives a real PAR → Authorize → Token exchange with <paramref name="scope"/> and returns the
    /// issued <c>access_token</c> and <c>id_token</c> from the wire response body — both minted by the
    /// production pipeline, never hand-built fixtures.
    /// </summary>
    private async Task<(string AccessToken, string IdToken)> DriveCodeExchangeAsync(
        TestHostShell host, VerifierKeyMaterial material, string scope)
    {
        PkceParameters pkce = PkceGeneration.Generate(
            TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, WellKnownHttpMethods.Post,
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body!, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode);
        string code = ExtractCode(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, WellKnownHttpMethods.Post,
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        return (
            ExtractFromBody(tokenResponse.Body!, "access_token"),
            ExtractFromBody(tokenResponse.Body!, "id_token"));
    }


    /// <summary>
    /// Validates <paramref name="token"/> as an access token against the host's real issuer and
    /// signing key — the relying-party side reconstructed from wire bytes only, the same shape
    /// <see cref="AzpMultiAudienceScenarioTests"/> uses for the ID-Token azp scenarios.
    /// </summary>
    private async Task<JwsAccessTokenValidationResult> ValidateAsAccessTokenAsync(
        string token, VerifierKeyMaterial material, string expectedAudience)
    {
        ServerVerificationKeyResolverDelegate resolveKey = (kid, tenant, ctx, ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, material.SigningKeyId.Value, StringComparison.Ordinal)
                    ? material.SigningPublicKey : null);

        return await JwsAccessTokenValidator.ValidateAsync(
            token,
            material.Registration.IssuerUri!.OriginalString,
            expectedAudience,
            resolveKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            tenantId: default,
            new ExchangeContext(),
            expectedAuthorizedParty: null,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Validates <paramref name="token"/> through <see cref="Oidc10IdTokenValidator"/> (the OIDC
    /// §3.1.3.7 ID Token path) against the host's real issuer and signing key.
    /// </summary>
    private async Task<Oidc10IdTokenValidationResult> ValidateAsIdTokenAsync(
        string token, VerifierKeyMaterial material, string expectedAudience)
    {
        ServerVerificationKeyResolverDelegate resolveKey = (kid, tenant, ctx, ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(
                string.Equals(kid.Value, material.SigningKeyId.Value, StringComparison.Ordinal)
                    ? material.SigningPublicKey : null);

        return await Oidc10IdTokenValidator.ValidateAsync(
            token,
            material.Registration.IssuerUri!.OriginalString,
            expectedAudience,
            resolveKey,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            tenantId: default,
            new ExchangeContext(),
            expectedAuthorizedParty: null,
            expectedNonce: null,
            trustedAudiences: null,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Validates a hand-built token against a locally resolved (non-host) key, mirroring <see cref="JwsAccessTokenValidatorTests"/>.</summary>
    private async Task<JwsAccessTokenValidationResult> ValidateStandaloneAsync(string token, PublicKeyMemory publicKey)
    {
        ServerVerificationKeyResolverDelegate resolver = (kid, tenant, ctx, ct) =>
            ValueTask.FromResult<PublicKeyMemory?>(string.Equals(kid.Value, StandaloneKid, StringComparison.Ordinal)
                ? publicKey : null);

        return await JwsAccessTokenValidator.ValidateAsync(
            token,
            StandaloneIssuer,
            StandaloneAudience,
            resolver,
            MicrosoftCryptographicFunctions.VerifyP256Async,
            JwsAccessTokenTestSupport.Parser,
            TestSetup.Base64UrlDecoder,
            TimeProvider,
            BaseMemoryPool.Shared,
            IatSkew,
            tenantId: default,
            new ExchangeContext(),
            expectedAuthorizedParty: null,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async ValueTask<ServerHttpResponse> DispatchUserInfoAsync(
        TestHostShell host, VerifierKeyMaterial material, string authorizationHeader)
    {
        string segment = material.Registration.TenantId.Value;
        string path = TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.UserInfo, segment);

        RequestHeaders headers = new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = [authorizationHeader]
        });

        IncomingRequest request = new(
            Path: path,
            Method: WellKnownHttpMethods.Post,
            Fields: new RequestFields(),
            Headers: headers,
            RouteValues: RouteValues.Empty);

        ExchangeContext context = new();
        context.SetTenantId(segment);

        return await host.Server.DispatchAsync(request, context, TestContext.CancellationToken)
            .ConfigureAwait(false);
    }


    private static ReadOnlySpan<byte> HeaderSerializer(JwtHeader header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);


    private static ReadOnlySpan<byte> PayloadSerializer(JwtPayload payload) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(property).GetString()!;
    }


    private static string ExtractCode(string location)
    {
        Uri uri = new(location);
        string query = uri.Query.TrimStart('?');
        foreach(string pair in query.Split('&'))
        {
            string[] parts = pair.Split('=', 2);
            if(parts.Length == 2 && parts[0] == "code")
            {
                return Uri.UnescapeDataString(parts[1]);
            }
        }

        throw new InvalidOperationException($"No code in redirect: {location}");
    }
}
