using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Did.Methods;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Core.Resolvers;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Vcalm;

namespace Verifiable.Tests.Vcalm;

/// <summary>
/// End-to-end tests of the W3C VCALM 1.0 conformance bridge over a real HTTPS loopback listener: the
/// §3.2.1 issue, §3.3.1 credential-verify and §3.3.2 presentation-verify interfaces served at the
/// stable, suite-expected flat paths behind an OAuth 2.0 bearer gate, with tokens minted by the
/// authorization server's own token endpoint over the same socket.
/// </summary>
/// <remarks>
/// <para>What the rows drive, one normative case each:</para>
/// <list type="bullet">
///   <item><description>
///   The positive path: a client-credentials token scoped and audienced for this instance issues a
///   credential (201) and verifies it (200), and the scope-prefix and audience-shape rows that must
///   be admitted.
///   </description></item>
///   <item><description>
///   The 401/403 split: no credentials or an unsupported scheme (401, realm-only challenge, empty
///   body), a token that fails validation or names another audience (401,
///   <c>error="invalid_token"</c>), and a valid token whose scope does not grant the path (403,
///   <c>error="insufficient_scope"</c> with the required scope). Each challenge is compared as the
///   literal header string.
///   </description></item>
///   <item><description>
///   The routing rows: every unserved path, the tenant-scoped dispatcher paths included, answers 404
///   with an empty body whatever token it carries; <c>GET</c> on a served path answers 405 with
///   <c>Allow: POST</c>.
///   </description></item>
///   <item><description>
///   The body rows: a body above the 10MB baseline reaches the issuer at a served path and is
///   answered with its 413 ProblemDetails; a body above the instance's own buffering bound gets the
///   instance's empty 413; the same body at an unserved path answers 404; a validation fault answers
///   500 with no challenge.
///   </description></item>
///   <item><description>
///   The fixture rows: an instance audience that cannot be a realm fails at construction, and the
///   shell refuses to rebind a running listener to another audience.
///   </description></item>
/// </list>
/// <para>
/// Every refusal row asserts that nothing reached the credential store or its load seam. The
/// signing and verification seams are the same library primitives the dispatch-level
/// <see cref="VcalmIssuerEndpointTests"/> uses; the bridge composes them over HTTPS.
/// </para>
/// </remarks>
[TestClass]
internal sealed class VcalmConformanceBridgeTests
{
    /// <summary>The MSTest context, the source of each test's cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fake clock the shell's authorization server mints and validates tokens against.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The memory pool the test passes to every pooled operation.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The conformance client's identifier at the authorization server.</summary>
    private const string ClientId = "https://conformance.client.test";

    /// <summary>The conformance client's <c>client_secret_post</c> secret.</summary>
    private const string ClientSecret = "vcalm-conformance-client-secret";

    /// <summary>The conformance client's base URI for registration.</summary>
    private static Uri ClientBaseUri { get; } = new("https://conformance.client.test");

    /// <summary>
    /// This instance's own resource identifier for the RFC 9068 §4 <c>aud</c> check and the challenge
    /// realm: a fixed value the test chooses and maps every served scope to, never the ephemeral
    /// loopback address the listener binds.
    /// </summary>
    private const string InstanceAudience = "https://vcalm-bridge.conformance.test";

    /// <summary>A second, unrelated instance identifier, for tokens minted for another resource.</summary>
    private const string OtherInstanceAudience = "https://other-bridge.conformance.test";

    /// <summary><see cref="InstanceAudience"/> with its host in another letter case.</summary>
    private const string CaseVariantAudience = "https://VCALM-bridge.conformance.test";

    /// <summary><see cref="InstanceAudience"/> with a trailing slash.</summary>
    private const string TrailingSlashAudience = InstanceAudience + "/";

    /// <summary><see cref="InstanceAudience"/> with the <c>https</c> default port written out.</summary>
    private const string DefaultPortAudience = "https://vcalm-bridge.conformance.test:443";

    /// <summary>
    /// An absolute IRI whose path holds a non-ASCII character, which an RFC 9110 quoted-string, and so
    /// a challenge <c>realm</c>, cannot carry.
    /// </summary>
    private const string UnrepresentableRealmAudience = "https://vcalm-bridge.conformance.test/instänce";

    /// <summary>The §3.2.1 issuance interface's scope.</summary>
    private const string IssueScope = "write:/credentials/issue";

    /// <summary>The §3.3.1 credential-verification interface's scope.</summary>
    private const string VerifyScope = "write:/credentials/verify";

    /// <summary>The §3.3.2 presentation-verification interface's scope.</summary>
    private const string PresentationsVerifyScope = "write:/presentations/verify";

    /// <summary>A <c>read:</c> scope for the issuance path, the wrong operation for a POST interface.</summary>
    private const string WrongOperationIssueScope = "read:/credentials/issue";

    /// <summary>The issuance scope with its operation in upper case, which the grammar does not define.</summary>
    private const string UppercaseOperationIssueScope = "WRITE:/credentials/issue";

    /// <summary>A scope for an interface this host does not serve.</summary>
    private const string UnservedEndpointScope = "write:/exchanges";

    /// <summary>A scope whose path is empty, which is not path-absolute.</summary>
    private const string MalformedEmptyPathScope = "write:";

    /// <summary>A scope whose path starts with <c>//</c>, which is not path-absolute.</summary>
    private const string DoubleSlashPathScope = "write://";

    /// <summary>The root scope of the instance.</summary>
    private const string RootWildcardScope = "write:/";

    /// <summary>A scope one segment above the issuance path, without a trailing slash.</summary>
    private const string CredentialsSegmentScope = "write:/credentials";

    /// <summary>A scope one segment above the issuance path, with a trailing slash.</summary>
    private const string CredentialsTrailingSlashScope = "write:/credentials/";

    /// <summary>A textual prefix of the issuance path that ends inside its last segment.</summary>
    private const string NonBoundaryPrefixScope = "write:/credentials/iss";

    /// <summary>A textual prefix of the issuance path that ends inside its first segment.</summary>
    private const string ShortNonBoundaryPrefixScope = "write:/cred";

    /// <summary>
    /// The <c>Basic</c> credential the unsupported-scheme row presents: <c>user:pass</c> base64-encoded
    /// as <see href="https://www.rfc-editor.org/rfc/rfc7617#section-2">RFC 7617 §2</see> defines, so the
    /// header is a well-formed credential under a scheme this resource does not accept.
    /// </summary>
    private const string BasicCredential = "dXNlcjpwYXNz";

    /// <summary>The literal response header name the challenge rows read.</summary>
    private const string WwwAuthenticateHeaderName = "WWW-Authenticate";

    /// <summary>The literal RFC 6750 §3.1 error code of a refused token.</summary>
    private const string InvalidTokenErrorCode = "invalid_token";

    /// <summary>The literal RFC 6750 §3.1 error code of an insufficient scope.</summary>
    private const string InsufficientScopeErrorCode = "insufficient_scope";

    /// <summary>
    /// The realm-only challenge, in the form of the RFC 6750 §3 example
    /// <c>WWW-Authenticate: Bearer realm="example"</c> with this instance as the realm.
    /// </summary>
    private const string RealmOnlyChallenge = "Bearer realm=\"" + InstanceAudience + "\"";

    /// <summary>
    /// The refused-token challenge, in the form of the RFC 6750 §3 example
    /// <c>Bearer realm="example", error="invalid_token"</c> with no <c>error_description</c>.
    /// </summary>
    private const string InvalidTokenChallenge = "Bearer realm=\"" + InstanceAudience + "\", error=\"invalid_token\"";

    /// <summary>
    /// The octets of JSON whitespace the oversized-body rows append: 10 × 2^20, so the body exceeds
    /// the 10MB baseline under the decimal and the binary reading of "MB" alike.
    /// </summary>
    private const int OversizePaddingLength = 10 * 1024 * 1024;

    /// <summary>
    /// The payload cap, in octets, the above-host-cap row configures the issuer with while the instance
    /// serves traffic: 64 × 2^10, far below the issuer's 10 × 2^20 default, so the instance's own bound
    /// (this cap plus one mebibyte) sits far below the default as well.
    /// </summary>
    private const long LoweredIssuerPayloadCap = 64 * 1024;

    /// <summary>
    /// The octets of JSON whitespace the above-host-cap row appends: 9 × 2^17 (1.125 mebibytes), above
    /// <see cref="LoweredIssuerPayloadCap"/> plus the one mebibyte the instance buffers beyond it, and
    /// below the issuer's 10 × 2^20 default, so only a bound that follows the configured cap refuses it
    /// before the issuer sees it.
    /// </summary>
    private const int AboveHostCapPaddingLength = 9 * 128 * 1024;

    /// <summary>The media type of the issuer's ProblemDetails body.</summary>
    private const string JsonMediaType = "application/json";

    /// <summary>
    /// The problem <c>type</c> URL the issuer's payload-size refusal carries: the Verifiable Credentials
    /// Data Model's malformed-value problem under the base URL the VCALM 1.0 Error Handling example uses.
    /// </summary>
    private const string PayloadTooLargeProblemType = "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR";

    /// <summary>The problem <c>title</c> the issuer's payload-size refusal carries.</summary>
    private const string PayloadTooLargeProblemTitle = "PAYLOAD_TOO_LARGE";

    /// <summary>
    /// The capabilities of the conformance tenant: the VCALM issuer and verifier roles, the
    /// client-credentials grant the bridge's tokens come from, and the authorization-code
    /// capability the RFC 9068 access-token producer is gated on. The discovery and JWKS
    /// capabilities stay enabled on the tenant for the authorization server's own wiring; the bridge
    /// serves neither endpoint.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> ConformanceCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownVcalmCapabilities.VcalmIssuer,
            WellKnownVcalmCapabilities.VcalmVerifier,
            WellKnownCapabilityIdentifiers.OAuthClientCredentials,
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);

    /// <summary>Every scope the conformance client may request, each mapped to <see cref="InstanceAudience"/>.</summary>
    private static ImmutableArray<string> RegisteredScopes { get; } =
    [
        IssueScope, VerifyScope, PresentationsVerifyScope, WrongOperationIssueScope, UppercaseOperationIssueScope,
        UnservedEndpointScope, MalformedEmptyPathScope, DoubleSlashPathScope, RootWildcardScope,
        CredentialsSegmentScope, CredentialsTrailingSlashScope, NonBoundaryPrefixScope, ShortNonBoundaryPrefixScope
    ];

    /// <summary>The serializer options the credential and claim codecs use.</summary>
    private static JsonSerializerOptions JsonOptions { get; } = TestSetup.DefaultSerializationOptions;

    /// <summary>The builder of the issuer's <c>did:key</c> document.</summary>
    private static KeyDidBuilder KeyDidBuilder { get; } = new();

    /// <summary>The <c>did:key</c> resolver the verification seam resolves the issuer with.</summary>
    private static DidResolver KeyDidResolverSeam { get; } = new(
        DidMethodSelectors.FromResolvers(
            (WellKnownDidMethodPrefixes.KeyDidMethodPrefix, KeyDidResolver.Build(Pool))));

    /// <summary>The RDFC canonicalizer both Data Integrity seams use.</summary>
    private static CanonicalizationDelegate RdfcCanonicalizer { get; } =
        CanonicalizationTestUtilities.CreateRdfcCanonicalizer();

    /// <summary>The JSON-LD context resolver both Data Integrity seams use.</summary>
    private static ContextResolverDelegate ContextResolver { get; } =
        CanonicalizationTestUtilities.CreateTestContextResolver();

    /// <summary>Serializes a credential for signing and verification.</summary>
    private static CredentialSerializeDelegate SerializeCredential { get; } = credential =>
        JsonSerializerExtensions.Serialize(credential, JsonOptions);

    /// <summary>Deserializes a credential for signing.</summary>
    private static CredentialDeserializeDelegate DeserializeCredential { get; } = serialized =>
        JsonSerializerExtensions.Deserialize<VerifiableCredential>(serialized, JsonOptions)!;

    /// <summary>Serializes Data Integrity proof options.</summary>
    private static ProofOptionsSerializeDelegate SerializeProofOptions { get; } =
        ProofOptionsSerializer.Create(JsonOptions);

    /// <summary>The key material each test creates, disposed at cleanup.</summary>
    private List<IDisposable> OwnedKeys { get; } = [];

    /// <summary>
    /// The storage seam's backing store, so a refusal row can assert that no issuance reached it and
    /// the retrieval row can find the issued credential; cleared between tests.
    /// </summary>
    private ConcurrentDictionary<string, VcalmStoredCredential> CredentialStore { get; } =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Counts calls into the storage seam's load delegate, so a refusal row can assert that no refused
    /// request reached VCALM's retrieval path. A field rather than a property because
    /// <see cref="Interlocked.Increment(ref int)"/> needs a storage location to increment.
    /// </summary>
    private int loadCallCount;


    /// <summary>Disposes the test's key material and clears the store and the load counter.</summary>
    [TestCleanup]
    public void DisposeOwnedKeys()
    {
        foreach(IDisposable key in OwnedKeys)
        {
            key.Dispose();
        }

        OwnedKeys.Clear();
        CredentialStore.Clear();
        loadCallCount = 0;
    }


    /// <summary>
    /// The positive path over HTTPS: a client-credentials token scoped to both interfaces and
    /// audienced for this instance issues a credential (201) and verifies it (200,
    /// <c>verified:true</c>).
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>:
    /// "write:/credentials/issue would allow a client to access the API endpoint for credential
    /// issuance on a particular issuer instance".
    /// </summary>
    [TestMethod]
    public async Task IssueThenVerifyOverHttpWithClientCredentialsToken()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string accessToken = await ObtainClientCredentialsTokenAsync(
            http, baseAddress, scope: $"{IssueScope} {VerifyScope}").ConfigureAwait(false);

        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:bridge-credential-1", SerializeCredential);
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
            "The §3.2.1 issue response over HTTPS carries a Data Integrity proof.");

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
            "A credential issued by the bridge's issuer endpoint must verify TRUE at its verifier endpoint over HTTPS.");
    }


    /// <summary>
    /// The token endpoint is public: a client obtains the token there without presenting one.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "the access tokens
    /// used by clients are expected to be OAuth 2.0 Bearer Tokens [RFC6750] or any other valid OAuth
    /// 2.0 token type. Any valid OAuth 2.0 grant type can be used to request the access tokens."
    /// </summary>
    [TestMethod]
    public async Task TokenEndpointAnswersWithoutBearerToken()
    {
        await using TestHostShell app = new(TimeProvider);
        _ = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);

        Assert.IsFalse(string.IsNullOrEmpty(token), "The token endpoint mints a token for an unauthenticated POST.");
    }


    /// <summary>
    /// A request with no <c>Authorization</c> header answers 401 with a realm-only challenge and an
    /// empty body. <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "If the request lacks any authentication information (e.g., the client was unaware that
    /// authentication is necessary or attempted using an unsupported authentication method), the
    /// resource server SHOULD NOT include an error code or other error information."
    /// </summary>
    [TestMethod]
    public async Task MissingAuthorizationHeaderGetsRealmOnlyChallenge()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:no-authorization", SerializeCredential);
        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, accessToken: null)
            .ConfigureAwait(false);

        await AssertRealmOnlyRefusalAsync(response).ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A request under the <c>Basic</c> scheme answers 401 with a realm-only challenge and an empty
    /// body. <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If
    /// the request lacks any authentication information (e.g., the client was unaware that
    /// authentication is necessary or attempted using an unsupported authentication method), the
    /// resource server SHOULD NOT include an error code or other error information."
    /// </summary>
    [TestMethod]
    public async Task UnsupportedSchemeGetsRealmOnlyChallenge()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:basic-scheme", SerializeCredential);
        using HttpResponseMessage response = await PostJsonWithSchemeAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody,
            ("Basic", BasicCredential)).ConfigureAwait(false);

        await AssertRealmOnlyRefusalAsync(response).ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A bearer value that is not a JWT answers 401 with <c>error="invalid_token"</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code."
    /// </summary>
    [TestMethod]
    public async Task MalformedBearerTokenIsInvalidToken()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:malformed-token", SerializeCredential);
        await AssertInvalidTokenAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, "not-a-real-jwt")
            .ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A <c>read:</c> scope does not grant a POST interface.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see> maps scopes "based
    /// on the HTTP method (e.g., GET -&gt; read, POST -&gt; write)", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "insufficient_scope The request requires higher privileges than provided by the access token.
    /// The resource server SHOULD respond with the HTTP 403 (Forbidden) status code and MAY include the
    /// "scope" attribute with the scope necessary to access the protected resource."
    /// </summary>
    [TestMethod]
    public async Task ReadScopeAtWriteInterfaceIsInsufficient()
    {
        await AssertIssueScopeRefusedAsync(WrongOperationIssueScope, "urn:uuid:read-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// A token whose granted scope is empty grants nothing: <c>openid</c> narrows to an empty scope
    /// under the client-credentials grant, and an explicit <c>resource</c> still binds the audience,
    /// so the refusal is on scope. <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC
    /// 6750 §3.1</see>: "insufficient_scope The request requires higher privileges than provided by
    /// the access token."
    /// </summary>
    [TestMethod]
    public async Task EmptyGrantedScopeIsInsufficient()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(
            http, baseAddress, scope: WellKnownScopes.OpenId, resource: InstanceAudience).ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:empty-scope", SerializeCredential);

        await AssertInsufficientScopeAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, token, IssueScope)
            .ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A validly audienced token re-signed without its <c>scope</c> claim grants nothing.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "insufficient_scope The request requires higher privileges than provided by the access token."
    /// </summary>
    [TestMethod]
    public async Task RemovedScopeClaimIsInsufficient()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string grantedToken = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);
        string scopeRemovedToken = await ReSignWithoutClaimAsync(
            grantedToken, WellKnownJwtClaimNames.Scope, ctx.HostMaterial).ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:scope-removed", SerializeCredential);

        await AssertInsufficientScopeAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, scopeRemovedToken,
            IssueScope).ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A scope for another API path does not grant the issuance path.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "Include the entire
    /// API path (excluding the domain and component instance, which are captured in aud) in the
    /// scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task UnservedEndpointScopeIsInsufficient()
    {
        await AssertIssueScopeRefusedAsync(UnservedEndpointScope, "urn:uuid:unserved-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// The issuance scope does not grant the presentation-verification path, and the challenge names
    /// the scope that would. <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
    /// §3.1</see>: "insufficient_scope ... MAY include the "scope" attribute with the scope necessary
    /// to access the protected resource."
    /// </summary>
    [TestMethod]
    public async Task IssueScopeAtPresentationsVerifyIsInsufficient()
    {
        await using TestHostShell app = new(TimeProvider);
        _ = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string issueOnlyToken = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);

        await AssertInsufficientScopeAsync(
            http, baseAddress, VcalmConformanceHttpApplication.PresentationsVerifyPath,
            "{\"verifiablePresentation\":{}}", issueOnlyToken, PresentationsVerifyScope).ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// The issuance scope does not grant the credential-verification path, and the challenge names
    /// the scope that would. <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750
    /// §3.1</see>: "insufficient_scope ... MAY include the "scope" attribute with the scope necessary
    /// to access the protected resource."
    /// </summary>
    [TestMethod]
    public async Task IssueScopeAtCredentialsVerifyIsInsufficient()
    {
        await using TestHostShell app = new(TimeProvider);
        _ = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string issueOnlyToken = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);

        await AssertInsufficientScopeAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsVerifyPath,
            "{\"verifiableCredential\":{}}", issueOnlyToken, VerifyScope).ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A scope whose path is empty (<c>write:</c>) is not path-absolute and grants nothing.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "scope = operation
    /// ":" path-absolute (defined in [RFC3986])".
    /// </summary>
    [TestMethod]
    public async Task MalformedEmptyPathScopeIsInsufficient()
    {
        await AssertIssueScopeRefusedAsync(MalformedEmptyPathScope, "urn:uuid:empty-path-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// A scope whose path starts with <c>//</c> (<c>write://</c>) is not path-absolute and grants
    /// nothing. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "scope =
    /// operation ":" path-absolute (defined in [RFC3986])".
    /// </summary>
    [TestMethod]
    public async Task DoubleSlashPathScopeIsInsufficient()
    {
        await AssertIssueScopeRefusedAsync(DoubleSlashPathScope, "urn:uuid:double-slash-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// An upper-case operation (<c>WRITE:</c>) is not one the grammar defines and grants nothing.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "operation =
    /// "read" / "write"".
    /// </summary>
    [TestMethod]
    public async Task UppercaseOperationScopeIsInsufficient()
    {
        await AssertIssueScopeRefusedAsync(UppercaseOperationIssueScope, "urn:uuid:uppercase-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// <c>write:/credentials/iss</c> is a textual prefix of the issuance path that ends inside a
    /// segment, not a path the issuance path contains as a prefix at a segment boundary, so it grants
    /// nothing. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "The write
    /// operation enables actions that create and/or update resources in the system to be performed on
    /// the provided path, or on any path that contains the provided path as a prefix."
    /// </summary>
    [TestMethod]
    public async Task NonBoundaryPrefixScopeIsInsufficient()
    {
        await AssertIssueScopeRefusedAsync(NonBoundaryPrefixScope, "urn:uuid:non-boundary-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// <c>write:/cred</c> ends inside the first segment of the issuance path, so it grants nothing.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "The write
    /// operation enables actions that create and/or update resources in the system to be performed on
    /// the provided path, or on any path that contains the provided path as a prefix."
    /// </summary>
    [TestMethod]
    public async Task ShortNonBoundaryPrefixScopeIsInsufficient()
    {
        await AssertIssueScopeRefusedAsync(ShortNonBoundaryPrefixScope, "urn:uuid:short-prefix-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// The root scope grants the issuance path.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "write:/ would
    /// allow a client to create and modify resources via any API on a particular instance".
    /// </summary>
    [TestMethod]
    public async Task RootWildcardScopeGrantsEveryWritePath()
    {
        await AssertIssueScopeAdmittedAsync(RootWildcardScope, "urn:uuid:root-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// <c>write:/credentials</c> grants <c>/credentials/issue</c>, a path that contains it as a prefix
    /// at a segment boundary. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM
    /// 1.0</see>: "The write operation enables actions that create and/or update resources in the
    /// system to be performed on the provided path, or on any path that contains the provided path as
    /// a prefix."
    /// </summary>
    [TestMethod]
    public async Task SegmentPrefixScopeGrantsTheNestedInterface()
    {
        await AssertIssueScopeAdmittedAsync(CredentialsSegmentScope, "urn:uuid:segment-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// <c>write:/credentials/</c> grants <c>/credentials/issue</c>, a path that contains it as a
    /// prefix. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "The write
    /// operation enables actions that create and/or update resources in the system to be performed on
    /// the provided path, or on any path that contains the provided path as a prefix."
    /// </summary>
    [TestMethod]
    public async Task TrailingSlashPrefixScopeGrantsTheNestedInterface()
    {
        await AssertIssueScopeAdmittedAsync(CredentialsTrailingSlashScope, "urn:uuid:trailing-slash-scope").ConfigureAwait(false);
    }


    /// <summary>
    /// A token minted for another instance through <c>resource</c> is refused as
    /// <c>invalid_token</c>. <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068
    /// §4</see>: "The JWT access token MUST be rejected if "aud" does not contain a resource indicator
    /// of the current resource server as a valid audience." and "the authorization server response
    /// MUST include the error code "invalid_token"."
    /// </summary>
    [TestMethod]
    public async Task OtherInstanceAudienceIsInvalidToken()
    {
        await AssertIssueAudienceRefusedAsync(OtherInstanceAudience, "urn:uuid:other-audience").ConfigureAwait(false);
    }


    /// <summary>
    /// A validly scoped token re-signed without its <c>aud</c> claim is refused as
    /// <c>invalid_token</c>. <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068
    /// §4</see>: "The resource server MUST validate that the "aud" claim contains a resource indicator
    /// value corresponding to an identifier the resource server expects for itself."
    /// </summary>
    [TestMethod]
    public async Task RemovedAudienceClaimIsInvalidToken()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string grantedToken = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);
        string audienceRemovedToken = await ReSignWithoutClaimAsync(
            grantedToken, WellKnownJwtClaimNames.Aud, ctx.HostMaterial).ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:audience-removed", SerializeCredential);

        await AssertInvalidTokenAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, audienceRemovedToken)
            .ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// An <c>aud</c> array holding this instance beside a number is neither shape
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see> defines,
    /// so the claim is malformed and refused as a whole rather than narrowed to its string entry.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>: "in case of any
    /// failure in the validation checks listed above, the authorization server response MUST include
    /// the error code "invalid_token"."
    /// </summary>
    [TestMethod]
    public async Task MixedTypeAudienceArrayIsInvalidToken()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string grantedToken = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);
        string mixedAudienceToken = await ReSignWithAudienceAsync(
            grantedToken, new object[] { InstanceAudience, 7 }, ctx.HostMaterial).ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:mixed-audience", SerializeCredential);

        await AssertInvalidTokenAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, mixedAudienceToken)
            .ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// An audience differing from this instance's identifier only in letter case is refused: the
    /// identifier this resource server expects for itself is the configured string, compared exactly.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>: "The JWT access
    /// token MUST be rejected if "aud" does not contain a resource indicator of the current resource
    /// server as a valid audience."
    /// </summary>
    [TestMethod]
    public async Task AudienceCaseVariantIsInvalidToken()
    {
        await AssertIssueAudienceRefusedAsync(CaseVariantAudience, "urn:uuid:case-variant-audience").ConfigureAwait(false);
    }


    /// <summary>
    /// An audience differing from this instance's identifier only by a trailing slash is refused: the
    /// comparison is exact, with no URI normalisation.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>: "The JWT access
    /// token MUST be rejected if "aud" does not contain a resource indicator of the current resource
    /// server as a valid audience."
    /// </summary>
    [TestMethod]
    public async Task AudienceTrailingSlashIsInvalidToken()
    {
        await AssertIssueAudienceRefusedAsync(TrailingSlashAudience, "urn:uuid:trailing-slash-audience").ConfigureAwait(false);
    }


    /// <summary>
    /// An audience differing from this instance's identifier only by the written-out default port
    /// (<c>:443</c>) is refused: the comparison is exact, with no URI normalisation.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>: "The JWT access
    /// token MUST be rejected if "aud" does not contain a resource indicator of the current resource
    /// server as a valid audience."
    /// </summary>
    [TestMethod]
    public async Task AudienceDefaultPortIsInvalidToken()
    {
        await AssertIssueAudienceRefusedAsync(DefaultPortAudience, "urn:uuid:default-port-audience").ConfigureAwait(false);
    }


    /// <summary>
    /// A token wrong on both axes, another instance's audience and a <c>read:</c> scope, is refused
    /// 401 <c>invalid_token</c>, not 403: token validation, the audience included, completes before the
    /// scope is judged. <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068
    /// §4</see>: "in case of any failure in the validation checks listed above, the authorization
    /// server response MUST include the error code "invalid_token"."
    /// </summary>
    [TestMethod]
    public async Task WrongAudienceWithWrongScopeIsInvalidTokenNotInsufficientScope()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(
            http, baseAddress, scope: WrongOperationIssueScope, resource: OtherInstanceAudience).ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:wrong-audience-and-scope", SerializeCredential);

        await AssertInvalidTokenAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, token)
            .ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A token minted with two <c>resource</c> values carries an <c>aud</c> array holding this instance
    /// among others, and is admitted. <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC
    /// 9068 §4</see>: "The resource server MUST validate that the "aud" claim contains a resource
    /// indicator value corresponding to an identifier the resource server expects for itself."
    /// </summary>
    [TestMethod]
    public async Task AudienceArrayHoldingTheInstanceIsAdmitted()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(
            http, baseAddress, IssueScope, [OtherInstanceAudience, InstanceAudience]).ConfigureAwait(false);

        await AssertIssuedAsync(http, baseAddress, ctx, token, "urn:uuid:audience-array").ConfigureAwait(false);
    }


    /// <summary>
    /// A token whose <c>aud</c> is the single string naming this instance, the one-audience form
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see> allows,
    /// is admitted. <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>:
    /// "The resource server MUST validate that the "aud" claim contains a resource indicator value
    /// corresponding to an identifier the resource server expects for itself."
    /// </summary>
    [TestMethod]
    public async Task SingleStringAudienceIsAdmitted()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string grantedToken = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);
        string singleStringAudienceToken = await ReSignWithAudienceAsync(
            grantedToken, InstanceAudience, ctx.HostMaterial).ConfigureAwait(false);

        await AssertIssuedAsync(http, baseAddress, ctx, singleStringAudienceToken, "urn:uuid:single-string-audience")
            .ConfigureAwait(false);
    }


    /// <summary>
    /// A POST with no token to the dispatcher's tenant-scoped issuance path answers 404 with an empty
    /// body: scopes name paths of this instance's API, and the tenant-scoped path is not one.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "Include the entire
    /// API path (excluding the domain and component instance, which are captured in aud) in the
    /// scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedIssuancePathBypassIsRefused()
    {
        await AssertTenantPathNotFoundAsync("vcalm/credentials/issue", tokenScope: null).ConfigureAwait(false);
    }


    /// <summary>
    /// A POST with a valid issuance token to the dispatcher's tenant-scoped issuance path answers 404
    /// with an empty body: a token grants paths of this instance's API, and the tenant-scoped path is
    /// not one. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "Include
    /// the entire API path (excluding the domain and component instance, which are captured in aud) in
    /// the scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedIssuancePathWithValidTokenIsNotFound()
    {
        await AssertTenantPathNotFoundAsync("vcalm/credentials/issue", IssueScope).ConfigureAwait(false);
    }


    /// <summary>
    /// A POST with no token to the dispatcher's tenant-scoped credential-verification path answers 404
    /// with an empty body. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>:
    /// "Include the entire API path (excluding the domain and component instance, which are captured
    /// in aud) in the scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedCredentialsVerifyPathWithoutTokenIsNotFound()
    {
        await AssertTenantPathNotFoundAsync("vcalm/credentials/verify", tokenScope: null).ConfigureAwait(false);
    }


    /// <summary>
    /// A POST with a valid verification token to the dispatcher's tenant-scoped credential-verification
    /// path answers 404 with an empty body.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "Include the entire
    /// API path (excluding the domain and component instance, which are captured in aud) in the
    /// scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedCredentialsVerifyPathWithValidTokenIsNotFound()
    {
        await AssertTenantPathNotFoundAsync("vcalm/credentials/verify", VerifyScope).ConfigureAwait(false);
    }


    /// <summary>
    /// A POST with no token to the dispatcher's tenant-scoped presentation-verification path answers
    /// 404 with an empty body. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM
    /// 1.0</see>: "Include the entire API path (excluding the domain and component instance, which are
    /// captured in aud) in the scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedPresentationsVerifyPathWithoutTokenIsNotFound()
    {
        await AssertTenantPathNotFoundAsync("vcalm/presentations/verify", tokenScope: null).ConfigureAwait(false);
    }


    /// <summary>
    /// A POST with a valid presentation-verification token to the dispatcher's tenant-scoped
    /// presentation-verification path answers 404 with an empty body.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "Include the entire
    /// API path (excluding the domain and component instance, which are captured in aud) in the
    /// scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedPresentationsVerifyPathWithValidTokenIsNotFound()
    {
        await AssertTenantPathNotFoundAsync("vcalm/presentations/verify", PresentationsVerifyScope).ConfigureAwait(false);
    }


    /// <summary>
    /// A POST with no token to the dispatcher's tenant-scoped issuance path with a trailing slash
    /// answers 404 with an empty body. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM
    /// 1.0</see>: "Include the entire API path (excluding the domain and component instance, which are
    /// captured in aud) in the scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedTrailingSlashOnIssuePathWithoutTokenIsNotFound()
    {
        await AssertTenantPathNotFoundAsync("vcalm/credentials/issue/", tokenScope: null).ConfigureAwait(false);
    }


    /// <summary>
    /// A POST with a valid issuance token to the dispatcher's tenant-scoped issuance path with a
    /// trailing slash answers 404 with an empty body.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM 1.0</see>: "Include the entire
    /// API path (excluding the domain and component instance, which are captured in aud) in the
    /// scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedTrailingSlashOnIssuePathWithValidTokenIsNotFound()
    {
        await AssertTenantPathNotFoundAsync("vcalm/credentials/issue/", IssueScope).ConfigureAwait(false);
    }


    /// <summary>
    /// <c>/credentials/issue/</c> is not the issuance path this instance serves, so a POST to it
    /// answers 404 with an empty body. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM
    /// 1.0</see>: "Include the entire API path (excluding the domain and component instance, which are
    /// captured in aud) in the scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TrailingSlashOnIssuePathIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:trailing-slash-path", SerializeCredential);
        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath + "/", issueBody,
            accessToken: null).ConfigureAwait(false);

        await AssertNotFoundWithEmptyBodyAsync(response).ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A <c>GET</c> on the POST-only issuance path, even with a token granting its <c>write:</c> scope,
    /// answers 405 with <c>Allow: POST</c> and no challenge, and reaches nothing: the path is known,
    /// the method is not served (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.6">RFC
    /// 9110 §15.5.6</see>), and <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM
    /// 1.0</see> maps scopes "based on the HTTP method (e.g., GET -&gt; read, POST -&gt; write)".
    /// </summary>
    [TestMethod]
    public async Task GetMethodOnIssuePathIsRefusedEvenWithAGrantingToken()
    {
        await using TestHostShell app = new(TimeProvider);
        _ = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);

        using HttpRequestMessage request = new(
            HttpMethod.Get, new Uri(baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using HttpResponseMessage response = await http.SendAsync(request, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.MethodNotAllowed, response.StatusCode,
            "A GET on the POST-only issuance path is a known resource under an unserved method.");

        //Allow is representation metadata, so the client exposes it on the content headers.
        Assert.IsTrue(response.Content.Headers.TryGetValues("Allow", out IEnumerable<string>? allowedMethods),
            "A 405 response carries the Allow header.");
        Assert.AreEqual("POST", allowedMethods!.Single());
        Assert.IsFalse(response.Headers.NonValidated.Contains(WwwAuthenticateHeaderName),
            "A 405 is answered before admission, so it carries no bearer challenge.");
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// After a legitimate issuance, an unauthenticated <c>GET</c> on the dispatcher's tenant-scoped
    /// retrieval path for that credential answers 404, never reaches the load seam, and never returns
    /// the stored credential. <see href="https://www.w3.org/TR/vcalm-1.0/#authorization">VCALM
    /// 1.0</see>: "Include the entire API path (excluding the domain and component instance, which are
    /// captured in aud) in the scopes configured for the OAuth 2.0 issuer".
    /// </summary>
    [TestMethod]
    public async Task TenantScopedRetrievalBypassIsRefused()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);
        const string CredentialId = "urn:uuid:retrieval-bypass-target";
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: CredentialId, SerializeCredential);
        using HttpResponseMessage issueResponse = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, token)
            .ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Created, issueResponse.StatusCode);
        Assert.HasCount(1, CredentialStore, "The seed issuance reaches the store.");
        VcalmStoredCredential seeded = CredentialStore[CredentialId];
        int loadCallCountAfterSeeding = Volatile.Read(ref loadCallCount);

        string tenantScopedCredentialPath =
            $"/connect/{ctx.Segment}/vcalm/credentials/{Uri.EscapeDataString(CredentialId)}";
        using HttpRequestMessage tenantGet = new(HttpMethod.Get, new Uri(baseAddress, tenantScopedCredentialPath));
        using HttpResponseMessage tenantGetResponse = await http.SendAsync(tenantGet, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string tenantGetBody = await tenantGetResponse.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.NotFound, tenantGetResponse.StatusCode, tenantGetBody);
        Assert.AreEqual(string.Empty, tenantGetBody, "The 404 carries no body, so never the stored credential.");
        Assert.IsFalse(tenantGetBody.Contains(seeded.VerifiableCredentialJson, StringComparison.Ordinal),
            "The refused response never carries the stored credential.");
        Assert.AreEqual(loadCallCountAfterSeeding, Volatile.Read(ref loadCallCount),
            "The refused retrieval never reaches the load seam.");
        Assert.HasCount(1, CredentialStore, "The refused retrieval leaves the store unchanged.");
    }


    /// <summary>
    /// A fault while validating the token (issuer resolution raising) answers 500 with no challenge.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see> requires the
    /// challenge when "the protected resource request does not include authentication credentials or
    /// does not contain an access token that enables access to the protected resource"; a server fault
    /// is neither, and this host sends none for it.
    /// </summary>
    [TestMethod]
    public async Task ServerFaultCarriesNoChallenge()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveIssuerAsync = static (_, _, _) =>
                throw new InvalidOperationException("Deliberate fault: issuer resolution unavailable.");
        }).ConfigureAwait(false);

        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:server-fault", SerializeCredential);
        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, token)
            .ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode,
            "A fault during token validation is a 500, distinct from every refusal.");
        Assert.IsFalse(response.Headers.NonValidated.Contains(WwwAuthenticateHeaderName),
            "A 500 server fault carries no bearer challenge.");
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A validly authorized issuance whose body exceeds the 10MB baseline the VCALM issuer enforces
    /// reaches that issuer and is answered by it: 413 with a JSON ProblemDetails body whose
    /// <c>type</c> is a URL and whose <c>title</c> names the payload-size problem, no challenge, and
    /// nothing stored.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#error-handling">VCALM 1.0 Error Handling</see>:
    /// "When an implementation detects an anomaly while processing a document, a ProblemDetails object
    /// can be used to report the issue to other software systems. The interfaces for these objects
    /// follow [RFC9457] to encode the data." and "The type key MUST be present and its value MUST be a
    /// URL identifying the type of problem."
    /// </summary>
    [TestMethod]
    public async Task OversizedBodyAtMappedPathIsPayloadTooLarge()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:oversized-body", SerializeCredential);
        string oversizedBody = issueBody + new string(' ', OversizePaddingLength);

        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, oversizedBody, token)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.RequestEntityTooLarge, response.StatusCode, body);
        Assert.AreEqual(JsonMediaType, response.Content.Headers.ContentType?.MediaType,
            "The issuer's 413 carries a JSON ProblemDetails body.");
        using JsonDocument problem = JsonDocument.Parse(body);
        Assert.AreEqual(PayloadTooLargeProblemType, problem.RootElement.GetProperty("type").GetString(), body);
        Assert.AreEqual(PayloadTooLargeProblemTitle, problem.RootElement.GetProperty("title").GetString(), body);
        Assert.IsFalse(response.Headers.NonValidated.Contains(WwwAuthenticateHeaderName),
            "A 413 after admission carries no bearer challenge.");
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#payload-sizes">VCALM 1.0 Payload Sizes</see>:
    /// "Larger transactions can trigger DoS incidents. It's recommended to configure the payload size
    /// accepted by endpoints at an instance level." With the issuer's payload cap configured down to
    /// 64 KiB while the instance serves traffic, a validly authorized issuance whose body exceeds that
    /// cap plus the one mebibyte this instance buffers beyond it, though it is well under the issuer's
    /// 10MB default, is refused by the instance before the issuer sees it: 413 with an empty body, no
    /// challenge, and nothing stored. The instance's bound follows the configured cap instead of the
    /// default.
    /// </summary>
    [TestMethod]
    public async Task BodyAboveHostCapAtMappedPathIsRefusedByHost()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmMaxRequestBytes = LoweredIssuerPayloadCap;
        }).ConfigureAwait(false);

        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: IssueScope)
            .ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:above-host-cap", SerializeCredential);
        string oversizedBody = issueBody + new string(' ', AboveHostCapPaddingLength);

        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, oversizedBody, token)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.RequestEntityTooLarge, response.StatusCode, body);
        Assert.AreEqual(string.Empty, body, "The instance's own 413 carries no body.");
        Assert.IsFalse(response.Headers.NonValidated.Contains(WwwAuthenticateHeaderName),
            "A 413 after admission carries no bearer challenge.");
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// A body above 10MB sent to a path this instance does not serve answers 404 with an empty body,
    /// not 413: routing runs on the method and the path before the body is read.
    /// <see href="https://www.w3.org/TR/vcalm-1.0/#payload-sizes-0">VCALM 1.0 Payload Sizes</see>: "A
    /// default maximum size of 10MB per verifiable credential is RECOMMENDED as an interoperability
    /// baseline".
    /// </summary>
    [TestMethod]
    public async Task OversizedBodyAtUnmappedPathIsNotFound()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:oversized-unmapped", SerializeCredential);
        string oversizedBody = issueBody + new string(' ', OversizePaddingLength);

        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, "/credentials/status", oversizedBody, accessToken: null).ConfigureAwait(false);

        await AssertNotFoundWithEmptyBodyAsync(response).ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// An instance audience that is an absolute IRI but cannot be carried as a challenge realm fails
    /// when the listener is started, before anything is bound, instead of at the first refusal.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>: "A "realm"
    /// attribute MAY be included to indicate the scope of protection in the manner described in
    /// HTTP/1.1 [RFC2617]."
    /// </summary>
    [TestMethod]
    public async Task UnrepresentableRealmFailsAtConstruction()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await ConfigureConformanceTenantAsync(app).ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<ArgumentException>(() => app.StartVcalmConformanceHostAsync(
            "default", ctx.HostMaterial.Registration, UnrepresentableRealmAudience, TestContext.CancellationToken))
            .ConfigureAwait(false);
        Assert.IsNull(app.Host("default").HttpBaseAddress, "A refused construction binds no listener.");
    }


    /// <summary>
    /// Once a listener serves this instance's audience, a later start naming another audience throws
    /// rather than leaving the test on a binding it did not ask for: the audience is "an identifier
    /// the resource server expects for itself"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>), so it is
    /// fixed for the listener's lifetime.
    /// </summary>
    [TestMethod]
    public async Task SecondStartNamingAnotherAudienceThrows()
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);

        _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(() => app.StartVcalmConformanceHostAsync(
            "default", ctx.HostMaterial.Registration, OtherInstanceAudience, TestContext.CancellationToken))
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Mints a token for <paramref name="scope"/> and asserts the issuance path refuses it 403 with
    /// the <c>insufficient_scope</c> challenge naming <see cref="IssueScope"/>, and that nothing
    /// reached storage.
    /// </summary>
    /// <param name="scope">The scope the token is minted for.</param>
    /// <param name="credentialId">The id of the credential the refused request would issue.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertIssueScopeRefusedAsync(string scope, string credentialId)
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: scope).ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId, SerializeCredential);

        await AssertInsufficientScopeAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, token, IssueScope)
            .ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// Mints a token for <paramref name="scope"/> and asserts the issuance path admits it (201).
    /// </summary>
    /// <param name="scope">The scope the token is minted for.</param>
    /// <param name="credentialId">The id of the credential the request issues.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertIssueScopeAdmittedAsync(string scope, string credentialId)
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: scope).ConfigureAwait(false);

        await AssertIssuedAsync(http, baseAddress, ctx, token, credentialId).ConfigureAwait(false);
    }


    /// <summary>
    /// Mints an issuance-scoped token whose audience is <paramref name="resource"/> and asserts the
    /// issuance path refuses it 401 with the <c>invalid_token</c> challenge, and that nothing reached
    /// storage.
    /// </summary>
    /// <param name="resource">The RFC 8707 <c>resource</c> value the token's audience is minted from.</param>
    /// <param name="credentialId">The id of the credential the refused request would issue.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertIssueAudienceRefusedAsync(string resource, string credentialId)
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string token = await ObtainClientCredentialsTokenAsync(
            http, baseAddress, scope: IssueScope, resource: resource).ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId, SerializeCredential);

        await AssertInvalidTokenAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, token)
            .ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// POSTs to <c>/connect/{segment}/</c><paramref name="tenantSuffix"/>, with a token for
    /// <paramref name="tokenScope"/> or with none, and asserts 404 with an empty body and that nothing
    /// reached storage.
    /// </summary>
    /// <param name="tenantSuffix">The dispatcher path below the tenant segment.</param>
    /// <param name="tokenScope">The scope of the presented token, or <see langword="null"/> for no token.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertTenantPathNotFoundAsync(string tenantSuffix, string? tokenScope)
    {
        await using TestHostShell app = new(TimeProvider);
        ConformanceContext ctx = await StartConformanceHostAsync(app).ConfigureAwait(false);
        HttpClient http = app.Host("default").SharedHttpClient!;
        Uri baseAddress = app.Host("default").HttpBaseAddress!;

        string? token = tokenScope is null
            ? null
            : await ObtainClientCredentialsTokenAsync(http, baseAddress, scope: tokenScope).ConfigureAwait(false);
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(
            ctx.IssuerDid, credentialId: "urn:uuid:tenant-path", SerializeCredential);

        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, $"/connect/{ctx.Segment}/{tenantSuffix}", issueBody, token).ConfigureAwait(false);

        await AssertNotFoundWithEmptyBodyAsync(response).ConfigureAwait(false);
        AssertNothingReachedStorage();
    }


    /// <summary>
    /// POSTs an issuance request with <paramref name="token"/> and asserts 201.
    /// </summary>
    /// <param name="http">The client pinned to the listener.</param>
    /// <param name="baseAddress">The listener's base address.</param>
    /// <param name="ctx">The conformance tenant's context.</param>
    /// <param name="token">The bearer token presented.</param>
    /// <param name="credentialId">The id of the credential issued.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertIssuedAsync(
        HttpClient http, Uri baseAddress, ConformanceContext ctx, string token, string credentialId)
    {
        string issueBody = VcalmWireFixtures.BuildIssueRequestBody(ctx.IssuerDid, credentialId, SerializeCredential);
        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, VcalmConformanceHttpApplication.CredentialsIssuePath, issueBody, token)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Created, response.StatusCode, body);
    }


    /// <summary>
    /// POSTs with <paramref name="accessToken"/> and asserts the RFC 6750 §3.1
    /// <c>insufficient_scope</c> refusal: 403, the literal challenge
    /// <c>Bearer realm="…", error="insufficient_scope", scope="…"</c> naming
    /// <paramref name="requiredScope"/>, and the JSON error body carrying the same code.
    /// </summary>
    /// <param name="http">The client pinned to the listener.</param>
    /// <param name="baseAddress">The listener's base address.</param>
    /// <param name="path">The request path.</param>
    /// <param name="jsonBody">The request body.</param>
    /// <param name="accessToken">The bearer token presented.</param>
    /// <param name="requiredScope">The scope the challenge must name.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertInsufficientScopeAsync(
        HttpClient http, Uri baseAddress, string path, string jsonBody, string accessToken, string requiredScope)
    {
        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, path, jsonBody, accessToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode, body);
        Assert.AreEqual(
            "Bearer realm=\"" + InstanceAudience + "\", error=\"insufficient_scope\", scope=\"" + requiredScope + "\"",
            ReadSingleChallenge(response));
        AssertWireErrorCode(InsufficientScopeErrorCode, body);
    }


    /// <summary>
    /// POSTs with <paramref name="accessToken"/> and asserts the refused-token shape: 401, the literal
    /// challenge <see cref="InvalidTokenChallenge"/> with neither an <c>error_description</c> nor a
    /// <c>scope</c> parameter, and the JSON error body carrying <c>invalid_token</c>.
    /// </summary>
    /// <param name="http">The client pinned to the listener.</param>
    /// <param name="baseAddress">The listener's base address.</param>
    /// <param name="path">The request path.</param>
    /// <param name="jsonBody">The request body.</param>
    /// <param name="accessToken">The bearer token presented.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertInvalidTokenAsync(
        HttpClient http, Uri baseAddress, string path, string jsonBody, string accessToken)
    {
        using HttpResponseMessage response = await PostJsonAsync(
            http, baseAddress, path, jsonBody, accessToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        string challenge = ReadSingleChallenge(response);
        Assert.AreEqual(InvalidTokenChallenge, challenge);
        Assert.IsFalse(challenge.Contains("error_description", StringComparison.Ordinal),
            "The invalid_token challenge carries no error_description.");
        Assert.IsFalse(challenge.Contains("scope=", StringComparison.Ordinal),
            "The invalid_token challenge carries no scope.");
        AssertWireErrorCode(InvalidTokenErrorCode, body);
    }


    /// <summary>
    /// Asserts the "no authentication information" refusal: 401, the literal challenge
    /// <see cref="RealmOnlyChallenge"/>, and an empty body.
    /// </summary>
    /// <param name="response">The response to judge.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertRealmOnlyRefusalAsync(HttpResponseMessage response)
    {
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.AreEqual(RealmOnlyChallenge, ReadSingleChallenge(response));
        Assert.AreEqual(string.Empty, body, "A request without authentication information gets no error body.");
    }


    /// <summary>Asserts a 404 with an empty body.</summary>
    /// <param name="response">The response to judge.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    private async Task AssertNotFoundWithEmptyBodyAsync(HttpResponseMessage response)
    {
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode, body);
        Assert.AreEqual(string.Empty, body, "The 404 carries no body.");
    }


    /// <summary>
    /// Asserts that no request reached VCALM storage: the credential store is empty and the load seam
    /// was never called.
    /// </summary>
    private void AssertNothingReachedStorage()
    {
        Assert.IsTrue(CredentialStore.IsEmpty, "No refused request reaches VCALM issuance.");
        Assert.AreEqual(0, Volatile.Read(ref loadCallCount), "No refused request reaches VCALM retrieval.");
    }


    /// <summary>
    /// Reads the single <c>WWW-Authenticate</c> value exactly as it arrived on the wire, from the
    /// client's non-validated header view so no client-side parsing rewrites it.
    /// </summary>
    /// <param name="response">The response carrying the challenge.</param>
    /// <returns>The raw challenge value.</returns>
    private static string ReadSingleChallenge(HttpResponseMessage response)
    {
        Assert.IsTrue(response.Headers.NonValidated.TryGetValues(WwwAuthenticateHeaderName, out HeaderStringValues challenges),
            "The refusal carries a WWW-Authenticate challenge.");
        Assert.HasCount(1, challenges, "The refusal carries exactly one challenge.");

        return challenges.ToString();
    }


    /// <summary>Asserts the JSON error body carries exactly <paramref name="expectedErrorCode"/>.</summary>
    /// <param name="expectedErrorCode">The literal error code expected.</param>
    /// <param name="responseBody">The response body.</param>
    private static void AssertWireErrorCode(string expectedErrorCode, string responseBody)
    {
        using JsonDocument document = JsonDocument.Parse(responseBody);
        Assert.AreEqual(expectedErrorCode, document.RootElement.GetProperty("error").GetString(),
            $"The refusal body carries the exact error code. Body: {responseBody}");
    }


    /// <summary>
    /// Configures the conformance tenant and starts the bridge listener for
    /// <see cref="InstanceAudience"/>.
    /// </summary>
    /// <param name="app">The shell the tenant and listener live in.</param>
    /// <returns>The tenant's context.</returns>
    private async Task<ConformanceContext> StartConformanceHostAsync(TestHostShell app)
    {
        ConformanceContext ctx = await ConfigureConformanceTenantAsync(app).ConfigureAwait(false);
        await app.StartVcalmConformanceHostAsync(
            "default", ctx.HostMaterial.Registration, InstanceAudience, TestContext.CancellationToken)
            .ConfigureAwait(false);

        return ctx;
    }


    /// <summary>
    /// Registers the conformance tenant (VCALM issuer and verifier, client credentials), maps every
    /// scope in <see cref="RegisteredScopes"/> to <see cref="InstanceAudience"/>, and wires the
    /// client-secret validator, the VCALM signing and verification seams and the storage seams,
    /// without starting a listener.
    /// </summary>
    /// <param name="app">The shell the tenant lives in.</param>
    /// <returns>The tenant's context.</returns>
    private async Task<ConformanceContext> ConfigureConformanceTenantAsync(TestHostShell app)
    {
        //RegisterDpopClient supplies the access-token signing keys and the scope-to-audience mapping
        //the RFC 9068 producer needs; the plain registration helper does not.
        VerifierKeyMaterial hostMaterial = await app.RegisterDpopClientAsync(
            ClientId, ClientBaseUri,
            profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ConformanceCapabilities).ConfigureAwait(false);
        OwnedKeys.Add(hostMaterial);

        foreach(string scope in RegisteredScopes)
        {
            _ = await app.AddScopeWithAudienceAsync(
                hostMaterial, scope, InstanceAudience, cancellationToken: TestContext.CancellationToken)
                .ConfigureAwait(false);
        }

        //client_secret_post (RFC 6749 §2.3.1): the application owns the secret store and comparison.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
                ValueTask.FromResult(
                    fields.TryGetValue("client_secret", out string? secret)
                    && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
        }).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        OwnedKeys.Add(issuerKeyPair.PublicKey);
        OwnedKeys.Add(issuerKeyPair.PrivateKey);

        DidDocument issuerDidDocument = await KeyDidBuilder.BuildAsync(
            issuerKeyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            Pool,
            includeDefaultContext: false,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string verificationMethodId = issuerDidDocument.VerificationMethod![0].Id!;
        string issuerDid = issuerDidDocument.Id!.ToString();

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultVcalmJsonParsing(JsonOptions);
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialIssuance = new VcalmCredentialIssuance
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
                        ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync
                    }
                ],
                ExistingProofHandling = VcalmExistingProofHandling.Error,
                SupportsMandatoryPointers = false,
                MemoryPool = Pool
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.StoreVcalmIssuedCredentialAsync = (credentialId, json, _, _) =>
            {
                CredentialStore[credentialId] = new VcalmStoredCredential { VerifiableCredentialJson = json };

                return ValueTask.CompletedTask;
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.LoadVcalmIssuedCredentialAsync = (credentialId, _, _) =>
            {
                _ = Interlocked.Increment(ref loadCallCount);

                return ValueTask.FromResult(CredentialStore.GetValueOrDefault(credentialId));
            };
        }).ConfigureAwait(false);

        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmCredentialVerification = new VcalmCredentialVerification
            {
                Resolver = KeyDidResolverSeam,
                Canonicalize = RdfcCanonicalizer,
                ContextResolver = ContextResolver,
                KnownContext = VcalmWireFixtures.CredentialKnownContext,
                DecodeProofValue = ProofValueCodecs.DecodeBase58Btc,
                SerializeCredential = SerializeCredential,
                SerializePresentation = presentation => JsonSerializerExtensions.Serialize(presentation, JsonOptions),
                SerializeProofOptions = SerializeProofOptions,
                Decoder = TestSetup.Base58Decoder,
                ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
                MemoryPool = Pool
            };
        }).ConfigureAwait(false);

        return new ConformanceContext(hostMaterial.Registration.TenantId.Value, issuerDid, hostMaterial);
    }


    /// <summary>
    /// Drives the RFC 6749 §4.4 client-credentials grant over HTTPS with <paramref name="scope"/> and,
    /// when supplied, one RFC 8707 <c>resource</c> value, so every token comes from the real token
    /// endpoint.
    /// </summary>
    /// <param name="http">The client pinned to the listener.</param>
    /// <param name="baseAddress">The listener's base address.</param>
    /// <param name="scope">The requested scope, or <see langword="null"/> for <c>openid</c>.</param>
    /// <param name="resource">The requested resource, or <see langword="null"/> for none.</param>
    /// <returns>The minted access token.</returns>
    private Task<string> ObtainClientCredentialsTokenAsync(
        HttpClient http, Uri baseAddress, string? scope = null, string? resource = null) =>
        ObtainClientCredentialsTokenAsync(
            http, baseAddress, scope ?? WellKnownScopes.OpenId, resource is null ? [] : [resource]);


    /// <summary>
    /// Drives the RFC 6749 §4.4 client-credentials grant over HTTPS with <paramref name="scope"/> and
    /// one <c>resource</c> parameter per entry of <paramref name="resources"/>.
    /// </summary>
    /// <param name="http">The client pinned to the listener.</param>
    /// <param name="baseAddress">The listener's base address.</param>
    /// <param name="scope">The requested scope.</param>
    /// <param name="resources">The requested resources, each sent as its own parameter.</param>
    /// <returns>The minted access token.</returns>
    private async Task<string> ObtainClientCredentialsTokenAsync(
        HttpClient http, Uri baseAddress, string scope, IReadOnlyList<string> resources)
    {
        Uri tokenUrl = new(baseAddress, VcalmConformanceHttpApplication.TokenPath);
        List<KeyValuePair<string, string>> fields =
        [
            new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.ClientCredentials),
            new(OAuthRequestParameterNames.ClientId, ClientId),
            new("client_secret", ClientSecret),
            new(OAuthRequestParameterNames.Scope, scope)
        ];
        foreach(string resource in resources)
        {
            fields.Add(new(OAuthRequestParameterNames.Resource, resource));
        }

        using FormUrlEncodedContent content = new(fields);
        using HttpResponseMessage response = await http.PostAsync(
            tokenUrl, content, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);

        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    /// <summary>
    /// Re-signs <paramref name="token"/> without <paramref name="claimName"/>: the shape of a claim the
    /// token endpoint never omits has to be produced this way to be tested at all.
    /// </summary>
    /// <param name="token">The minted token.</param>
    /// <param name="claimName">The claim removed.</param>
    /// <param name="material">The authorization server's signing material.</param>
    /// <returns>The re-signed token.</returns>
    private Task<string> ReSignWithoutClaimAsync(string token, string claimName, VerifierKeyMaterial material) =>
        ReSignAsync(token, claims => { _ = claims.Remove(claimName); }, material);


    /// <summary>
    /// Re-signs <paramref name="token"/> with its <c>aud</c> claim replaced by <paramref name="audience"/>.
    /// </summary>
    /// <param name="token">The minted token.</param>
    /// <param name="audience">The replacement <c>aud</c> value.</param>
    /// <param name="material">The authorization server's signing material.</param>
    /// <returns>The re-signed token.</returns>
    private Task<string> ReSignWithAudienceAsync(string token, object audience, VerifierKeyMaterial material) =>
        ReSignAsync(token, claims => claims[WellKnownJwtClaimNames.Aud] = audience, material);


    /// <summary>
    /// Decodes <paramref name="token"/>'s claims into a pooled buffer, applies <paramref name="mutate"/>,
    /// and re-signs the result with <paramref name="material"/>'s own signing key and key id.
    /// </summary>
    /// <param name="token">The minted token.</param>
    /// <param name="mutate">The change applied to the decoded claims.</param>
    /// <param name="material">The authorization server's signing material.</param>
    /// <returns>The re-signed token.</returns>
    private async Task<string> ReSignAsync(string token, Action<Dictionary<string, object>> mutate, VerifierKeyMaterial material)
    {
        string encodedPayload = token.Split('.')[1];
        Dictionary<string, object> claims;
        using(IMemoryOwner<byte> payloadOwner = Pool.Rent(Base64Url.GetMaxDecodedLength(encodedPayload.Length)))
        {
            int payloadLength = Base64Url.DecodeFromChars(encodedPayload, payloadOwner.Memory.Span);
            claims = JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                payloadOwner.Memory.Span[..payloadLength], JsonOptions)!;
        }

        mutate(claims);

        JwtHeader header = JwtHeader.ForAccessToken(WellKnownJwaValues.Es256, material.SigningKeyId.Value);
        UnsignedJwt unsignedJwt = new(header, new JwtPayload(claims));

        using JwsMessage jws = await unsignedJwt.SignAsync(
            material.SigningPrivateKey,
            ReSignHeaderSerializer,
            ReSignPayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>The JWS header serializer <see cref="ReSignAsync"/> signs with.</summary>
    /// <param name="header">The header.</param>
    /// <returns>The header's UTF-8 JSON.</returns>
    private static ReadOnlySpan<byte> ReSignHeaderSerializer(JwtHeader header) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)header, JsonOptions);


    /// <summary>The JWS payload serializer <see cref="ReSignAsync"/> signs with.</summary>
    /// <param name="payload">The payload.</param>
    /// <returns>The payload's UTF-8 JSON.</returns>
    private static ReadOnlySpan<byte> ReSignPayloadSerializer(JwtPayload payload) =>
        JsonSerializerExtensions.SerializeToUtf8Bytes((Dictionary<string, object>)payload, JsonOptions);


    /// <summary>
    /// POSTs <paramref name="jsonBody"/> under the <c>Bearer</c> scheme when
    /// <paramref name="accessToken"/> is supplied, or with no <c>Authorization</c> header when
    /// <see langword="null"/>.
    /// </summary>
    /// <param name="http">The client pinned to the listener.</param>
    /// <param name="baseAddress">The listener's base address.</param>
    /// <param name="path">The request path.</param>
    /// <param name="jsonBody">The request body.</param>
    /// <param name="accessToken">The bearer token, or <see langword="null"/>.</param>
    /// <returns>The response.</returns>
    private Task<HttpResponseMessage> PostJsonAsync(
        HttpClient http, Uri baseAddress, string path, string jsonBody, string? accessToken) =>
        PostJsonWithSchemeAsync(
            http, baseAddress, path, jsonBody, accessToken is null ? null : ("Bearer", accessToken));


    /// <summary>
    /// POSTs <paramref name="jsonBody"/> with an <c>Authorization</c> header built from
    /// <paramref name="schemeAndParameter"/>, or with none when <see langword="null"/>.
    /// </summary>
    /// <param name="http">The client pinned to the listener.</param>
    /// <param name="baseAddress">The listener's base address.</param>
    /// <param name="path">The request path.</param>
    /// <param name="jsonBody">The request body.</param>
    /// <param name="schemeAndParameter">The authorization scheme and its parameter, or <see langword="null"/>.</param>
    /// <returns>The response.</returns>
    private async Task<HttpResponseMessage> PostJsonWithSchemeAsync(
        HttpClient http, Uri baseAddress, string path, string jsonBody, (string Scheme, string Parameter)? schemeAndParameter)
    {
        Uri url = new(baseAddress, path);
        using HttpRequestMessage request = new(HttpMethod.Post, url)
        {
            Content = new StringContent(jsonBody, Encoding.UTF8, WellKnownMediaTypes.Application.Json)
        };
        if(schemeAndParameter is (string scheme, string parameter))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(scheme, parameter);
        }

        //SendAsync transmits the whole request before it returns, so the request message can be
        //disposed here; the response is independent of it.
        return await http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads a secured credential's first Data Integrity proof, whether <c>proof</c> is an object or an array.</summary>
    /// <param name="securedCredential">The secured credential.</param>
    /// <returns>The first proof.</returns>
    private static JsonElement FirstProof(JsonElement securedCredential)
    {
        JsonElement proof = securedCredential.GetProperty(VcalmParameterNames.Proof);

        return proof.ValueKind == JsonValueKind.Array ? proof[0] : proof;
    }


    /// <summary>
    /// The conformance tenant's segment, the issuer DID the issue requests declare, and the
    /// authorization server's key material the re-sign helpers sign with.
    /// </summary>
    /// <param name="Segment">The conformance tenant's identifier, also the dispatcher's path segment.</param>
    /// <param name="IssuerDid">The <c>did:key</c> the issued credentials declare as their issuer.</param>
    /// <param name="HostMaterial">The authorization server's signing material and the tenant's registration.</param>
    private sealed record ConformanceContext(string Segment, string IssuerDid, VerifierKeyMaterial HostMaterial);
}
