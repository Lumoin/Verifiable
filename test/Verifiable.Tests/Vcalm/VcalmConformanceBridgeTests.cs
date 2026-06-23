using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Vcalm;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// The W3C VCALM 1.0 conformance bridge end-to-end test (chunk V-6a): the in-repo proof that the
/// §3.2.1 issue and §3.3.1 verify interfaces serve over REAL Kestrel HTTP at the stable,
/// suite-expected flat paths behind an OAuth2 client-credentials bearer gate — the exact path the
/// external <c>vc-api-issuer-test-suite</c> / <c>vc-api-verifier-test-suite</c> JS suites would drive
/// when pointed at this host (V-6b). The flow over the wire is:
/// </summary>
/// <remarks>
/// <list type="number">
///   <item><description>
///   A machine client obtains a Bearer access token from the AS token endpoint
///   (<c>POST /token</c>, <c>grant_type=client_credentials</c>) — RFC 6749 §4.4 / RFC 9068.
///   </description></item>
///   <item><description>
///   With that token, <c>POST /credentials/issue</c> returns HTTP 201 and a Data-Integrity-secured
///   credential (eddsa-rdfc-2022 over a did:key controller, project crypto + the RDFC canonicalizer).
///   </description></item>
///   <item><description>
///   That credential, POSTed to <c>POST /credentials/verify</c> with the token, returns HTTP 200 with
///   <c>verified:true</c> — the issue→verify round-trip across the socket.
///   </description></item>
///   <item><description>
///   Both protected endpoints answer HTTP 401 when the token is missing or invalid.
///   </description></item>
/// </list>
/// <para>
/// The Kestrel listener contends for sockets with the other HTTP lifecycle tests under Workers=4; it
/// passes in isolation like <see cref="Verifiable.Tests.OAuth.MultiHostHttpLifecycleTests"/>. The
/// VCALM signing / verification seams are the same library primitives the dispatch-level
/// <see cref="VcalmIssuerEndpointTests"/> uses — the bridge COMPOSES them over real HTTP, it does not
/// re-roll cryptography.
/// </para>
/// </remarks>
[TestClass]
internal sealed class VcalmConformanceBridgeTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://conformance.client.test";
    private const string ClientSecret = "vcalm-conformance-client-secret";
    private static readonly Uri ClientBaseUri = new("https://conformance.client.test");

    //The conformance tenant carries every capability the bridge exercises: the VCALM issuer / verifier
    //roles AND the OAuth grants the protection path needs. The RFC 9068 access-token producer is gated
    //on OAuthAuthorizationCode, so it rides alongside OAuthClientCredentials.
    private static readonly ImmutableHashSet<CapabilityIdentifier> ConformanceCapabilities =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmIssuer,
            WellKnownVcalmCapabilities.VcalmVerifier,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);

    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    private List<IDisposable> OwnedKeys { get; } = [];

    //The §3.2.2 storage seam-backed store, retained so the issued credential is reachable for the
    //round-trip; cleared between tests.
    private ConcurrentDictionary<string, VcalmStoredCredential> CredentialStore { get; } =
        new(StringComparer.Ordinal);


    [TestCleanup]
    public void DisposeOwnedKeys()
    {
        foreach(IDisposable key in OwnedKeys)
        {
            key.Dispose();
        }

        OwnedKeys.Clear();
        CredentialStore.Clear();
    }


    /// <summary>
    /// The bridge's money shot over real HTTP: client-credentials token → §3.2.1 issue (201) →
    /// §3.3.1 verify (200, verified:true), every exchange across the Kestrel socket with the Bearer
    /// token; and a 401 on each protected endpoint when the token is absent or invalid.
    /// </summary>
    [TestMethod]
    public async Task IssueThenVerifyOverHttpWithClientCredentialsToken()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        //=== Step 1: obtain the client-credentials Bearer access token over HTTP. ===
        string accessToken = await ObtainClientCredentialsTokenAsync(http, baseAddress).ConfigureAwait(false);

        //=== Step 2: POST a credential to /credentials/issue WITH the token → 201 secured VC. ===
        string issueBody = BuildIssueRequestBody(ctx.IssuerDid, credentialId: "urn:uuid:bridge-credential-1");
        using HttpResponseMessage issueResponse = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, accessToken)
            .ConfigureAwait(false);

        string issueResponseBody = await issueResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Created, issueResponse.StatusCode, issueResponseBody);

        using JsonDocument issued = JsonDocument.Parse(issueResponseBody);
        JsonElement securedCredential = issued.RootElement.GetProperty(VcalmParameterNames.VerifiableCredential);
        Assert.AreEqual("DataIntegrityProof",
            FirstProof(securedCredential).GetProperty("type").GetString(),
            "The §3.2.1 issue response over HTTP carries a Data Integrity proof.");

        //=== Step 3: POST that VC to /credentials/verify WITH the token → 200 verified:true. ===
        string verifyBody = "{\"verifiableCredential\":" + securedCredential.GetRawText()
            + ",\"options\":{\"returnProblemDetails\":true}}";
        using HttpResponseMessage verifyResponse = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsVerifyPath, verifyBody, accessToken)
            .ConfigureAwait(false);

        string verifyResponseBody = await verifyResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, verifyResponse.StatusCode, verifyResponseBody);

        using JsonDocument verifyDoc = JsonDocument.Parse(verifyResponseBody);
        Assert.IsTrue(verifyDoc.RootElement.GetProperty(VcalmParameterNames.Verified).GetBoolean(),
            "A credential issued by the bridge's issuer endpoint must verify TRUE at its verifier endpoint over HTTP.");
    }


    /// <summary>
    /// The OAuth2 protection gate: an issue / verify request with NO Authorization header, and one
    /// with a malformed token, are each rejected with HTTP 401 before dispatch — the request never
    /// reaches the VCALM endpoint.
    /// </summary>
    [TestMethod]
    public async Task ProtectedEndpointsReturn401WithoutValidToken()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string issueBody = BuildIssueRequestBody(ctx.IssuerDid, credentialId: "urn:uuid:unauth");

        //No token at all → 401.
        using HttpResponseMessage noToken = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, accessToken: null)
            .ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, noToken.StatusCode,
            "A VCALM protected-resource request without a Bearer token is 401.");

        //A structurally invalid token → 401 (it fails BearerTokenValidation's structural parse).
        using HttpResponseMessage badToken = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsVerifyPath, issueBody,
            accessToken: "not-a-real-jwt").ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, badToken.StatusCode,
            "A VCALM protected-resource request with an invalid token is 401.");

        //The token endpoint itself stays reachable unauthenticated — it mints the token.
        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress).ConfigureAwait(false);
        Assert.IsFalse(string.IsNullOrEmpty(token), "The unprotected token endpoint mints a token.");
    }


    /// <summary>
    /// Brings up the conformance Kestrel host: registers the conformance tenant (VCALM issuer +
    /// verifier + client-credentials), wires the client-secret validator, the VCALM signing /
    /// verification seams, and the storage seams, then starts the
    /// <see cref="VcalmConformanceHttpApplication"/> over loopback Kestrel. Returns the configured
    /// issuer DID the issue request must declare.
    /// </summary>
    private async Task<ConformanceContext> StartConformanceHostAsync(TestHostShell app)
    {
        //RegisterDpopClient supplies the AccessTokenIssuance signing keys and the ScopeToAudience
        //mapping the RFC 9068 producer needs; the plain RegisterClient helper does not.
        VerifierKeyMaterial hostMaterial = app.RegisterDpopClient(
            ClientId, ClientBaseUri,
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ConformanceCapabilities);
        OwnedKeys.Add(hostMaterial);

        //client_secret_post (RFC 6749 §2.3.1): the application owns the secret store and comparison.
        app.Server.OAuth().ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(
                fields.TryGetValue("client_secret", out string? secret)
                && string.Equals(secret, ClientSecret, StringComparison.Ordinal));

        //The VCALM issuer identity: an Ed25519 did:key controller the eddsa-rdfc-2022 descriptor signs as.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        OwnedKeys.Add(issuerKeyPair.PublicKey);
        OwnedKeys.Add(issuerKeyPair.PrivateKey);

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerKeyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        VcalmIntegration vcalm = app.Server.Vcalm();
        vcalm.UseDefaultVcalmJsonParsing(JsonOptions);

        vcalm.VcalmCredentialIssuance = new VcalmCredentialIssuance
        {
            ConfiguredIssuer = issuerDid,
            SigningDescriptors =
            [
                new VcalmProofDescriptor
                {
                    PrivateKey = issuerKeyPair.PrivateKey,
                    VerificationMethodId = verificationMethodId,
                    Cryptosuite = EddsaRdfc2022CryptosuiteInfo.Instance,
                    Canonicalize = RdfcCanonicalizer,
                    ContextResolver = ContextResolver,
                    EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
                    SerializeCredential = SerializeCredential,
                    DeserializeCredential = DeserializeCredential,
                    SerializeProofOptions = SerializeProofOptions,
                    Encoder = TestSetup.Base58Encoder,
                    ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync
                }
            ],
            ExistingProofHandling = VcalmExistingProofHandling.Error,
            SupportsMandatoryPointers = false,
            MemoryPool = Pool
        };

        vcalm.StoreVcalmIssuedCredentialAsync = (credentialId, json, _, _) =>
        {
            CredentialStore[credentialId] = new VcalmStoredCredential { VerifiableCredentialJson = json };

            return ValueTask.CompletedTask;
        };
        vcalm.LoadVcalmIssuedCredentialAsync = (credentialId, _, _) =>
            ValueTask.FromResult(CredentialStore.GetValueOrDefault(credentialId));

        vcalm.VcalmCredentialVerification = new VcalmCredentialVerification
        {
            Resolver = KeyDidResolverSeam,
            Canonicalize = RdfcCanonicalizer,
            ContextResolver = ContextResolver,
            DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
            SerializeCredential = SerializeCredential,
            SerializePresentation = presentation => JsonSerializerExtensions.Serialize(presentation, JsonOptions),
            SerializeProofOptions = SerializeProofOptions,
            Decoder = TestSetup.Base58Decoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,
            MemoryPool = Pool
        };

        await app.StartVcalmConformanceHostAsync(
            "default", hostMaterial.Registration, TestContext.CancellationToken).ConfigureAwait(false);

        return new ConformanceContext(hostMaterial.Registration.TenantId.Value, issuerDid);
    }


    private async Task<string> ObtainClientCredentialsTokenAsync(HttpClient http, Uri baseAddress)
    {
        Uri tokenUrl = new(baseAddress, VcalmConformanceHttpApplication.TokenPath);
        using FormUrlEncodedContent content = new(new Dictionary<string, string>
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            ["client_secret"] = ClientSecret,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        });

        using HttpResponseMessage response = await http.PostAsync(
            tokenUrl, content, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    private async Task<HttpResponseMessage> PostJsonAsync(
        HttpClient http, Uri baseAddress, string path, string jsonBody, string? accessToken)
    {
        Uri url = new(baseAddress, path);
        using HttpRequestMessage request = new(HttpMethod.Post, url)
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, WellKnownMediaTypes.Application.Json)
        };
        if(accessToken is not null)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                WellKnownAuthenticationSchemes.Bearer, accessToken);
        }

        //SendAsync fully transmits the request before returning, so the request message can be
        //disposed here; the response the caller reads is independent of it.
        return await http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static JsonElement FirstProof(JsonElement securedCredential)
    {
        JsonElement proof = securedCredential.GetProperty(VcalmParameterNames.Proof);

        return proof.ValueKind == JsonValueKind.Array ? proof[0] : proof;
    }


    private static string BuildIssueRequestBody(string issuerDid, string credentialId)
    {
        VerifiableCredential credential = new()
        {
            Context = new Context
            {
                Contexts =
                [
                    Context.Credentials20,
                    CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl
                ]
            },
            Id = credentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialSubject =
            [
                new CredentialSubject
                {
                    Id = "did:example:alumni-subject",
                    AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["alumniOf"] = "The School of Examples"
                    }
                }
            ]
        };

        return "{\"credential\":" + SerializeCredential(credential) + "}";
    }


    //The configured issuer DID the issue request declares, and the tenant segment the host fronts.
    private sealed record ConformanceContext(string Segment, string IssuerDid);
}
