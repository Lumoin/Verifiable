using System.Linq;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OpenID Connect Core 1.0 §12.2 real-wire proving test: a REFRESHED id_token must carry a fresh
/// <c>iat</c> (OIDC-099), the SAME <c>sid</c> the original End-User session established (OIDC-103),
/// the SAME <c>cnf.jkt</c> DPoP binding (RFC 9449 §6), and must still release the §5.4 standard
/// claims the granted <c>profile</c>/<c>email</c> scopes authorize.
/// <see cref="Verifiable.OAuth.AuthCode.Server.States.ServerRefreshTokenIssuedState"/> is the state
/// that carries <c>SessionId</c>/<c>Confirmation</c> across rotation;
/// <see cref="Verifiable.OAuth.SidClaimContributor"/>, <see cref="Verifiable.OAuth.CnfClaimContributor"/>,
/// and <see cref="Verifiable.OAuth.OidcStandardClaimsContributor"/> are the emission seams under test.
/// </summary>
/// <remarks>
/// <para>
/// Drives PAR → Authorize → Token → Refresh against a real Kestrel <see cref="LoopbackTls"/> host. PAR,
/// token, and refresh all run over the genuine TLS wire
/// (<see cref="OAuthTestTransport.PostFormAsync(System.Net.Http.HttpClient, Uri, IReadOnlyDictionary{string, string}, OutgoingHeaders?, System.Threading.CancellationToken)"/>);
/// the authorize leg dispatches in-process on the SAME <see cref="EndpointServer"/> instance the Kestrel
/// host serves, mirroring <see cref="RefreshedIdTokenAuthContextTests"/> and <see cref="SessionIdClaimTests"/>.
/// </para>
/// <para>
/// The token and refresh legs each present a real RFC 9449 DPoP proof for the SAME key, built directly
/// (not through <see cref="Verifiable.OAuth.AuthCode.AuthCodeClient.RefreshAsync(Verifiable.OAuth.Client.ClientRegistration, Verifiable.OAuth.AuthCode.RefreshTokenRequest, System.Threading.CancellationToken)"/>,
/// whose current wiring does not attach a DPoP proof — see the integrator notes on this wave). The
/// refresh leg's bound thumbprint forces <c>dpopRequired=true</c> server-side
/// (<see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation"/>), so a nonce-less proof
/// there deterministically draws one RFC 9449 §8.1 <c>use_dpop_nonce</c> challenge; the helper retries
/// once with the echoed nonce, mirroring the production client's own retry shape.
/// </para>
/// <para>
/// Non-vacuity: <c>iat</c> is asserted STRICTLY greater after advancing the shared
/// <see cref="FakeTimeProvider"/> between issuance and refresh — a producer that stamped a stale or
/// constant value would fail this, not merely pass coincidentally. <c>sid</c>/<c>cnf.jkt</c> are
/// asserted equal to values captured off the ORIGINAL id_token's wire bytes — a regression that fails
/// to carry <see cref="Verifiable.OAuth.AuthCode.Server.States.ServerRefreshTokenIssuedState.SessionId"/>
/// or <see cref="Verifiable.OAuth.AuthCode.Server.States.ServerRefreshTokenIssuedState.Confirmation"/>
/// across rotation drops or changes the claim, which fails the equality. The standard claims are
/// asserted present by name AND by value on the
/// refreshed token — a regression that gated the standard-claims contributors off the refresh grant
/// type would omit them entirely, which fails the presence check.
/// </para>
/// </remarks>
[TestClass]
internal sealed class RefreshedIdTokenParityTests
{
    /// <summary>MSTest's per-test context, supplying the cancellation token every wire call runs under.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the DPoP proofs share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://refreshed-id-token-parity.client.test";

    private const string SubjectId = "subject-refreshed-parity-01";

    /// <summary>The authenticate-time session identifier — the §12.2 "original" the refreshed id_token must repeat.</summary>
    private const string SessionId = "session-refreshed-parity-01";

    private const string ExpectedName = "Parity Test Subject";

    private const string ExpectedEmail = "parity-subject@example.test";

    private static readonly Uri ClientBaseUri = new(ClientId);

    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    private static readonly string Scope =
        $"{WellKnownScopes.OpenId} {WellKnownScopes.Profile} {WellKnownScopes.Email}";


    /// <summary>
    /// Drives authorization_code + PKCE + PAR under a DPoP-bound, session-established client with
    /// <c>openid profile email</c>, decodes the initial id_token, redeems the refresh token under the
    /// SAME DPoP key, decodes the refreshed id_token, and asserts iat freshness, sid parity, §5.4
    /// standard-claim parity, and cnf.jkt parity.
    /// </summary>
    [TestMethod]
    public async Task RefreshedIdTokenCarriesFreshIatAndParitySidClaimsAndCnf()
    {
        await using TestHostShell host = new(TimeProvider);
        host.SeedTestSubject(subject: SubjectId, name: ExpectedName, email: ExpectedEmail, emailVerified: true);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);
        host.EnableDpop();

        await host.StartHttpHostAsync(cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopMaterial =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            DpopKey dpopKey = new(dpopMaterial, WellKnownJwaValues.Es256);
            string expectedThumbprint = dpopKey.GetThumbprint(TestHostShell.Base64UrlEncoder, TestHostShell.MemoryPool);

            //1. PAR over the real wire.
            PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, BaseMemoryPool.Shared);
            Uri parUrl = new(
                hosted.HttpBaseAddress!,
                TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));
            using HttpResponseMessage parResponse = await OAuthTestTransport.PostFormAsync(
                hosted.SharedHttpClient!, parUrl, new Dictionary<string, string>
                {
                    [OAuthRequestParameterNames.ClientId] = ClientId,
                    [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
                    [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
                    [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
                    [OAuthRequestParameterNames.Scope] = Scope
                }, TestContext.CancellationToken).ConfigureAwait(false);
            string parBody = await parResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(201, (int)parResponse.StatusCode, parBody);
            string requestUri = ExtractRequestUri(parBody);

            //2. Authorize — in-process on the SAME EndpointServer the Kestrel host serves, establishing
            //   the End-User session (SetSessionId) the refreshed id_token's sid must repeat.
            ExchangeContext authorizeContext = new();
            authorizeContext.SetSubjectId(SubjectId);
            authorizeContext.SetSessionId(SessionId);
            RequestFields authorizeFields = new()
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RequestUri] = requestUri
            };
            ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
                segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
                authorizeFields, authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
            string code = TestBrowser.ExtractQueryParam(authorizeResponse.Location!, OAuthRequestParameterNames.Code)
                ?? throw new InvalidOperationException("Authorize redirect Location missing code.");

            //3. Token exchange over the real wire, presenting a DPoP proof for the key the confirmation
            //   binding will carry. Rfc6749WithPkce does not REQUIRE DPoP, so this leg needs no nonce
            //   round-trip — a well-formed proof is accepted and bound on the first attempt.
            Uri tokenUrl = new(hosted.HttpBaseAddress!, $"/connect/{segment}/token");
            Dictionary<string, string> tokenFields = new()
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
            };
            using HttpResponseMessage tokenResponse = await PostTokenEndpointWithDpopAsync(
                hosted.SharedHttpClient!, tokenUrl, tokenFields, dpopKey, material.Registration, segment)
                .ConfigureAwait(false);
            string tokenBody = await tokenResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)tokenResponse.StatusCode, tokenBody);

            using JsonDocument tokenDoc = JsonDocument.Parse(tokenBody);
            Assert.IsTrue(tokenDoc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out JsonElement initialIdTokenElement),
                $"openid in scope on authorization_code must mint an id_token. Body: {tokenBody}");
            string initialIdToken = initialIdTokenElement.GetString()!;
            string refreshToken = tokenDoc.RootElement.GetProperty(WellKnownTokenTypes.RefreshToken).GetString()!;

            using JsonDocument initialPayload = JwtPayloadDecoding.DecodePayload(initialIdToken, BaseMemoryPool.Shared);
            JsonElement initialClaims = initialPayload.RootElement;
            long tOrig = initialClaims.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64();
            string sidOrig = initialClaims.GetProperty(WellKnownJwtClaimNames.Sid).GetString()!;
            string nameOrig = initialClaims.GetProperty(WellKnownJwtClaimNames.Name).GetString()!;
            string emailOrig = initialClaims.GetProperty(WellKnownJwtClaimNames.Email).GetString()!;
            bool emailVerifiedOrig = initialClaims.GetProperty(WellKnownJwtClaimNames.EmailVerified).GetBoolean();
            string jktOrig = initialClaims.GetProperty(WellKnownJwtClaimNames.Cnf)
                .GetProperty(WellKnownJwtClaimNames.JwkThumbprint).GetString()!;

            //Sanity: the initial mint actually carried the established session and DPoP binding, and
            //released the granted profile/email claims — otherwise the parity assertions below would be
            //comparing against values the fix has no obligation to reproduce.
            Assert.AreEqual(SessionId, sidOrig, "Sanity: the initial id_token's sid must be the established session identifier.");
            Assert.AreEqual(ExpectedName, nameOrig, "Sanity: the initial id_token must release the profile-scope name claim.");
            Assert.AreEqual(ExpectedEmail, emailOrig, "Sanity: the initial id_token must release the email-scope email claim.");
            Assert.IsTrue(emailVerifiedOrig, "Sanity: the initial id_token must release email_verified.");
            Assert.AreEqual(expectedThumbprint, jktOrig, "Sanity: the initial id_token's cnf.jkt must equal the DPoP key's RFC 7638 thumbprint.");

            //4. Advance the clock — a regression stamping a stale/constant iat on refresh would now
            //   produce an observably WRONG (non-fresh) id_token.
            TimeProvider.Advance(TimeSpan.FromMinutes(15));

            //5. Refresh over the real wire, presenting a DPoP proof for the SAME key. The bound
            //   confirmation forces dpopRequired=true server-side, so the first (nonce-less) proof
            //   deterministically draws a use_dpop_nonce challenge; the helper retries with the
            //   echoed nonce.
            Dictionary<string, string> refreshFields = new()
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
                [OAuthRequestParameterNames.RefreshToken] = refreshToken,
                [OAuthRequestParameterNames.ClientId] = ClientId
            };
            using HttpResponseMessage refreshResponse = await PostTokenEndpointWithDpopAsync(
                hosted.SharedHttpClient!, tokenUrl, refreshFields, dpopKey, material.Registration, segment)
                .ConfigureAwait(false);
            string refreshBody = await refreshResponse.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)refreshResponse.StatusCode, refreshBody);

            using JsonDocument refreshDoc = JsonDocument.Parse(refreshBody);
            Assert.IsTrue(refreshDoc.RootElement.TryGetProperty(WellKnownTokenTypes.IdToken, out JsonElement refreshedIdTokenElement),
                $"A DPoP-bound refresh token minted alongside an authorization_code grant must still yield an id_token on redemption. Body: {refreshBody}");
            string refreshedIdToken = refreshedIdTokenElement.GetString()!;

            using JsonDocument refreshedPayload = JwtPayloadDecoding.DecodePayload(refreshedIdToken, BaseMemoryPool.Shared);
            JsonElement refreshedClaims = refreshedPayload.RootElement;

            //THE LOAD-BEARING OIDC-099 ASSERTION: iat is a fresh issuance time, strictly later than the
            //original — not a stale or carried-over value.
            long tRefreshed = refreshedClaims.GetProperty(WellKnownJwtClaimNames.Iat).GetInt64();
            Assert.IsGreaterThan(tOrig, tRefreshed,
                "OIDC-099: a refreshed id_token's iat must be strictly later than the original id_token's iat.");

            //THE LOAD-BEARING OIDC-103 §12.2/sid ASSERTION: sid is carried, not dropped or re-derived.
            Assert.IsTrue(refreshedClaims.TryGetProperty(WellKnownJwtClaimNames.Sid, out JsonElement sidRefreshedElement),
                "OIDC-103: the refreshed id_token must still carry sid.");
            Assert.AreEqual(sidOrig, sidRefreshedElement.GetString(),
                "OIDC-103 §12.2: the refreshed id_token's sid must equal the original id_token's sid.");

            //THE LOAD-BEARING §5.4 ASSERTION: per-scope standard-claim release survives refresh.
            Assert.IsTrue(refreshedClaims.TryGetProperty(WellKnownJwtClaimNames.Name, out JsonElement nameRefreshedElement),
                "OIDC Core §5.4: the refreshed id_token must still release the profile-scope name claim.");
            Assert.AreEqual(nameOrig, nameRefreshedElement.GetString(),
                "OIDC Core §5.4: the refreshed id_token's name claim must equal the original's.");
            Assert.IsTrue(refreshedClaims.TryGetProperty(WellKnownJwtClaimNames.Email, out JsonElement emailRefreshedElement),
                "OIDC Core §5.4: the refreshed id_token must still release the email-scope email claim.");
            Assert.AreEqual(emailOrig, emailRefreshedElement.GetString(),
                "OIDC Core §5.4: the refreshed id_token's email claim must equal the original's.");
            Assert.IsTrue(refreshedClaims.TryGetProperty(WellKnownJwtClaimNames.EmailVerified, out JsonElement emailVerifiedRefreshedElement),
                "OIDC Core §5.4: the refreshed id_token must still release email_verified.");
            Assert.AreEqual(emailVerifiedOrig, emailVerifiedRefreshedElement.GetBoolean(),
                "OIDC Core §5.4: the refreshed id_token's email_verified must equal the original's.");

            //THE LOAD-BEARING RFC 9449 §6/cnf ASSERTION: the DPoP binding is carried, not dropped.
            Assert.IsTrue(refreshedClaims.TryGetProperty(WellKnownJwtClaimNames.Cnf, out JsonElement cnfRefreshedElement),
                "RFC 9449 §6: the refreshed id_token must still carry cnf when the refresh was DPoP-bound.");
            string jktRefreshed = cnfRefreshedElement.GetProperty(WellKnownJwtClaimNames.JwkThumbprint).GetString()!;
            Assert.AreEqual(jktOrig, jktRefreshed,
                "RFC 9449 §6: the refreshed id_token's cnf.jkt must equal the original id_token's cnf.jkt.");
            Assert.AreEqual(expectedThumbprint, jktRefreshed,
                "RFC 9449 §6: the refreshed id_token's cnf.jkt must equal the DPoP key's RFC 7638 thumbprint.");
        }
        finally
        {
            dpopMaterial.PublicKey.Dispose();
            dpopMaterial.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Posts <paramref name="formFields"/> to the token endpoint with a DPoP proof for
    /// <paramref name="dpopKey"/>. When the first (nonce-less) attempt draws an RFC 9449 §8.1
    /// <c>use_dpop_nonce</c> challenge (400 + a <c>DPoP-Nonce</c> response header — the ONLY failure
    /// path in <see cref="Verifiable.OAuth.AuthCode.Server.DpopTokenEndpointValidation"/> that sets that
    /// header), retries once with the echoed nonce.
    /// </summary>
    private async Task<HttpResponseMessage> PostTokenEndpointWithDpopAsync(
        HttpClient httpClient,
        Uri tokenUrl,
        Dictionary<string, string> formFields,
        DpopKey dpopKey,
        ClientRecord clientRegistration,
        string segment)
    {
        string firstProof = await BuildTokenEndpointDpopProofAsync(dpopKey, clientRegistration, segment, nonce: null)
            .ConfigureAwait(false);
        HttpResponseMessage firstResponse = await OAuthTestTransport.PostFormAsync(
            httpClient, tokenUrl, formFields, OutgoingHeaders.Empty.WithDpop(firstProof),
            TestContext.CancellationToken).ConfigureAwait(false);

        if((int)firstResponse.StatusCode != 400
            || !firstResponse.Headers.TryGetValues(WellKnownHttpHeaderNames.DPoPNonce, out IEnumerable<string>? nonceValues))
        {
            return firstResponse;
        }

        string freshNonce = nonceValues!.First();
        firstResponse.Dispose();

        string retryProof = await BuildTokenEndpointDpopProofAsync(dpopKey, clientRegistration, segment, freshNonce)
            .ConfigureAwait(false);

        return await OAuthTestTransport.PostFormAsync(
            httpClient, tokenUrl, formFields, OutgoingHeaders.Empty.WithDpop(retryProof),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Builds a token-endpoint DPoP proof (<c>htm=POST</c>, <c>htu=</c> the issuer-authority + token
    /// path the server validates against per RFC 9449 §4.2) for <paramref name="dpopKey"/>.
    /// </summary>
    private async Task<string> BuildTokenEndpointDpopProofAsync(
        DpopKey dpopKey, ClientRecord clientRegistration, string segment, string? nonce)
    {
        string htu = $"{clientRegistration.IssuerUri!.GetLeftPart(UriPartial.Authority)}/connect/{segment}/token";
        DpopProofClaims claims = new()
        {
            Htm = WellKnownHttpMethods.Post,
            Htu = htu,
            Iat = TimeProvider.GetUtcNow(),
            Jti = Guid.NewGuid().ToString("N"),
            Nonce = nonce
        };

        return await DpopProofConstruction.BuildAsync(
            claims, dpopKey, TestHostShell.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctions.SignP256Async, TestHostShell.MemoryPool,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads the <c>request_uri</c> from a PAR response body.</summary>
    private static string ExtractRequestUri(string body)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty("request_uri").GetString()!;
    }
}
