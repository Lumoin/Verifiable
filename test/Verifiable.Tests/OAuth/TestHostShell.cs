using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.Tests.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.States;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Server.Registration;
namespace Verifiable.Tests.OAuth;

/// <summary>
/// An in-memory test host that mirrors what a production ASP.NET application does
/// at startup: creates an <see cref="AuthorizationServer"/> instance, wires all I/O
/// delegates to in-memory stores, subscribes to events, and registers clients.
/// </summary>
/// <remarks>
/// <para>
/// This is the test equivalent of <c>Program.cs</c>. In production the host is
/// ASP.NET with Kestrel, Dapper, PostgreSQL, and whatever other infrastructure
/// the deployment requires. Here the host is a plain class with
/// <see cref="ConcurrentDictionary{TKey,TValue}"/> stores. The
/// <see cref="AuthorizationServer"/> underneath is identical in both cases.
/// </para>
/// <para>
/// The host is responsible for infrastructure concerns only: key material storage,
/// flow state persistence, client registration routing, issuer trust resolution,
/// and HTTP dispatch. It never contains protocol logic, cryptographic verification,
/// or flow state machine knowledge — those belong to the library. The host provides
/// delegates that connect the library to external storage and trust frameworks.
/// </para>
/// <para>
/// Every test suite uses this — Auth Code PKCE, OID4VP, Federation, attack
/// mitigation — differing only in which capabilities each registered client has.
/// All algorithms are registered: P-256, P-384, P-521, Ed25519, secp256k1,
/// RSA-2048, ML-DSA-44/65/87. The key type used per client is determined at
/// registration time.
/// </para>
/// <para>
/// The host does NOT contain client actions. Browser redirect simulation lives
/// in <see cref="TestBrowser"/>. OAuth client logic lives in
/// <see cref="AuthCodeClient"/>. Wallet logic lives in <see cref="TestWallet"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("TestHostShell Clients={Registrations.Count} Flows={FlowStates.Count}")]
internal sealed class TestHostShell: IDisposable
{
    private ConcurrentDictionary<string, ClientRecord> Registrations { get; } = new();
    private ConcurrentDictionary<string, (OAuthFlowState State, int StepCount)> FlowStates { get; } = new();
    private ConcurrentDictionary<string, string> RequestUriTokenIndex { get; } = new();
    private ConcurrentDictionary<string, string> CodeIndex { get; } = new();
    private ConcurrentDictionary<string, string> JtiIndex { get; } = new();
    private ConcurrentDictionary<string, string> AccessTokenIndex { get; } = new();
    private ConcurrentDictionary<KeyId, PrivateKeyMemory> SigningKeys { get; } = new();
    private ConcurrentDictionary<KeyId, PublicKeyMemory> VerificationKeys { get; } = new();
    private ConcurrentDictionary<KeyId, PrivateKeyMemory> DecryptionKeys { get; } = new();
    private ConcurrentDictionary<string, string> RegistrationAccessTokens { get; } = new();
    private List<IDisposable> DpopOwnedDisposables { get; } = [];
    private InProcessHmacKeyResolver? DpopHmacResolver { get; set; }
    private bool Disposed { get; set; }

    /// <summary>Base64Url encoder shared by tests with the host's own wiring.</summary>
    public static EncodeDelegate Base64UrlEncoder => TestSetup.Base64UrlEncoder;

    /// <summary>Base64Url decoder shared by tests with the host's own wiring.</summary>
    public static DecodeDelegate Base64UrlDecoder => TestSetup.Base64UrlDecoder;

    /// <summary>The memory pool used by the host for sensitive allocations.</summary>
    public static MemoryPool<byte> MemoryPool => SensitiveMemoryPool<byte>.Shared;

    /// <summary>
    /// Constant tenant segment used by dynamic-registration tests. The
    /// global RFC 7591 POST has no segment in the URL, so the test transport
    /// supplies this value to <see cref="RegistrationEndpoints.HandleCreateAsync"/>.
    /// All dynamically-registered clients in tests share this tenant.
    /// </summary>
    private const string DynamicRegistrationTenant = "dynamic-clients";

    /// <summary>
    /// The AS's issuer URI for dynamic-registration tests. Returned by
    /// <see cref="GlobalRegistrationEndpoint"/> for the host root and used as
    /// <see cref="ClientRegistration.AuthorizationServerIssuer"/> on the
    /// resulting registration.
    /// </summary>
    public Uri IssuerUri { get; } = new($"https://issuer.test/{DynamicRegistrationTenant}");

    /// <summary>
    /// The global RFC 7591 §3 registration endpoint URL. Used by
    /// dynamic-registration tests as the value of
    /// <see cref="RegisterClientOptions.RegistrationEndpoint"/>.
    /// </summary>
    public Uri GlobalRegistrationEndpoint { get; } =
        new("https://verifier.example.com/connect/register");


    /// <summary>The authorization server instance. All tests dispatch through this.</summary>
    public AuthorizationServer Server { get; }

    /// <summary>The current registration routing table.</summary>
    public IReadOnlyDictionary<string, ClientRecord> RegistrationStore => Registrations;

    /// <summary>The server-side flow state store.</summary>
    public IReadOnlyDictionary<string, (OAuthFlowState State, int StepCount)> FlowStore => FlowStates;

    /// <summary>The time provider injected at construction.</summary>
    public TimeProvider Time { get; }

    /// <summary>
    /// Issuer trust store mapping issuer identifiers to their public keys.
    /// The verifier uses this to verify credential issuer signatures.
    /// </summary>
    private Dictionary<string, PublicKeyMemory> IssuerTrustStore { get; } = [];


    /// <summary>
    /// Registers a trusted issuer's public key for credential signature verification.
    /// </summary>
    /// <param name="issuerId">The issuer identifier (the <c>iss</c> claim value).</param>
    /// <param name="issuerPublicKey">The issuer's public key.</param>
    public void RegisterIssuerTrust(string issuerId, PublicKeyMemory issuerPublicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerId);
        ArgumentNullException.ThrowIfNull(issuerPublicKey);

        IssuerTrustStore[issuerId] = issuerPublicKey;
    }


    /// <summary>
    /// Creates a fully wired test application with in-memory stores and all
    /// cryptographic algorithms registered.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The constructor mirrors production startup: all codec, hash, signing,
    /// verification, and key agreement functions are registered via
    /// <see cref="TestSetup.Setup"/> (the <c>[ModuleInitializer]</c>) before this
    /// constructor runs. The server options resolve delegates from those registries,
    /// exactly as a production application would.
    /// </para>
    /// </remarks>
    /// <param name="timeProvider">
    /// Time provider for all timestamps. Pass <c>FakeTimeProvider</c> in tests.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Delegate that resolves an issuer's public key from its identifier.
    /// When <see langword="null"/>, the default resolver reads from
    /// <see cref="IssuerTrustStore"/>.
    /// </param>
    /// <param name="vpValidator">
    /// VP token validator. When <see langword="null"/>, HAIP 1.0 SD-JWT rules are used.
    /// </param>
    public TestHostShell(
        TimeProvider timeProvider,
        ResolveIssuerKeyDelegate? resolveIssuerKey = null,
        ClaimIssuer<ValidationContext>? vpValidator = null)
    {
        ArgumentNullException.ThrowIfNull(timeProvider);

        Time = timeProvider;

        resolveIssuerKey ??= ResolveIssuerKey;
        vpValidator ??= new ClaimIssuer<ValidationContext>(
            "vp-haip10-verifier",
            ValidationProfiles.Haip10SdJwtRules(),
            timeProvider);

        AuthorizationServerIntegration integration = new()
        {
            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult(ctx.TenantId),

            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    Registrations.TryGetValue(tenantId, out ClientRecord? reg)
                        ? reg : null),

            SaveFlowStateAsync = (tenantId, flowId, state, stepCount, ctx, ct) =>
            {
                FlowStates[flowId] = (state, stepCount);

                //Build secondary indexes from the state so that continuing
                //endpoints can resolve external handles back to the flowId.
                //This mirrors SQL indexed columns on the same row.
                //Single-tenant fixture: tenantId is accepted to match the delegate
                //signature but not used in the keying. Multi-tenant tests would key
                //by (tenantId, flowId) compounds.
                switch(state)
                {
                    case Verifiable.OAuth.AuthCode.Server.States.ParRequestReceivedState par:
                    {
                        string token = ExtractRequestUriToken(par.RequestUri);
                        if(!string.IsNullOrWhiteSpace(token))
                        {
                            RequestUriTokenIndex[token] = flowId;
                        }

                        break;
                    }
                    case Verifiable.OAuth.AuthCode.Server.States.ServerCodeIssuedState codeIssued:
                    {
                        CodeIndex[codeIssued.CodeHash] = flowId;
                        break;
                    }
                    case Verifiable.OAuth.Oid4Vp.Server.States.VerifierParReceivedState vpPar:
                    {
                        //The OID4VP PAR endpoint stamps the per-flow handle directly on
                        //the state. No URL parsing — the handle is first-class.
                        if(!string.IsNullOrWhiteSpace(vpPar.ParHandle))
                        {
                            RequestUriTokenIndex[vpPar.ParHandle] = flowId;
                        }

                        break;
                    }
                    case JtiSeenState jti:
                    {
                        //RFC 9449 §11.1 replay defense. The flowId arrives already
                        //composed as "{issuer}:{jti}" so the AS-side handler can
                        //pre-resolve via ResolveCorrelationKeyAsync without rebuilding
                        //the composite key. The index value is the same composite key
                        //and presence in the dictionary is the replay signal.
                        JtiIndex[$"{jti.Issuer}:{jti.Jti}"] = flowId;
                        break;
                    }
                    case ServerTokenIssuedState:
                    {
                        //Capture access_token → flowId so test code can recover the
                        //BoundJwkThumbprint binding for a known access token. The
                        //IssuedTokenSet carries the live JWS strings on the request
                        //context (they are never persisted onto state).
                        string? accessToken = ctx.IssuedTokens?.AccessToken;
                        if(!string.IsNullOrEmpty(accessToken))
                        {
                            AccessTokenIndex[accessToken] = flowId;
                        }

                        break;
                    }
                }

                return ValueTask.CompletedTask;
            },

            LoadFlowStateAsync = (tenantId, flowId, ctx, ct) =>
                ValueTask.FromResult(
                    FlowStates.TryGetValue(flowId, out var entry)
                        ? (entry.State, entry.StepCount)
                        : ((OAuthFlowState?)null, 0)),

            ResolveCorrelationKeyAsync = (tenantId, flowKind, externalHandle, ctx, ct) =>
            {
                //DPoP replay lookup is keyed specifically by flow kind: the AS
                //pre-composes "{issuer}:{jti}" and asks under FlowKind.JtiReplay.
                //Other flows fall through to the general secondary indexes.
                if(flowKind == FlowKind.JtiReplay)
                {
                    return ValueTask.FromResult<string?>(
                        JtiIndex.TryGetValue(externalHandle, out string? jtiFlowId)
                            ? jtiFlowId : null);
                }

                //Try each secondary index. The application knows which handle
                //types exist — this mirrors a SQL query with OR conditions.
                if(RequestUriTokenIndex.TryGetValue(externalHandle, out string? flowId))
                {
                    return ValueTask.FromResult<string?>(flowId);
                }

                if(CodeIndex.TryGetValue(externalHandle, out flowId))
                {
                    return ValueTask.FromResult<string?>(flowId);
                }

                //Not found in any index.
                return ValueTask.FromResult<string?>(null);
            },

            //URL composition for the discovery document and any token claims that
            //embed endpoint URLs. The library never composes paths; it asks here.
            //Test fixture serves a /connect/{segment}/<suffix> path family rooted
            //at registration.IssuerUri (or the per-request issuer placed by the
            //skin on context). Production deployments may use sub-domains, header
            //routing, or any other scheme.
            ResolveEndpointUriAsync = (endpointKey, registration, ctx, ct) =>
            {
                Uri? baseUri = registration.IssuerUri ?? ctx.Issuer;
                if(baseUri is null)
                {
                    return ValueTask.FromResult<Uri?>(null);
                }

                string authority = baseUri.GetLeftPart(UriPartial.Authority);
                string segment = registration.TenantId.Value;

                //Per-flow OID4VP request_uri: incorporate the per-flow handle the
                //library placed on the context. The URL shape is the deployment's
                //choice; this fixture uses /connect/{segment}/request/{handle}.
                if(string.Equals(endpointKey, Oid4VpEndpointKeys.RequestUri, StringComparison.Ordinal))
                {
                    string? handle = ctx.ParHandle;
                    if(string.IsNullOrWhiteSpace(handle))
                    {
                        return ValueTask.FromResult<Uri?>(null);
                    }

                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}/connect/{segment}/request/{handle}"));
                }

                //Switch expressions over string require constant patterns; these
                //metadata keys moved from `const string` to `static readonly string`
                //for cross-assembly data-block sharing, so the dispatch is written
                //as an equality chain instead.
                string? suffix;
                if(endpointKey == AuthorizationServerMetadataKeys.JwksUri)
                {
                    suffix = "jwks";
                }
                else if(endpointKey == AuthorizationServerMetadataKeys.PushedAuthorizationRequestEndpoint)
                {
                    suffix = "par";
                }
                else if(endpointKey == AuthorizationServerMetadataKeys.AuthorizationEndpoint)
                {
                    suffix = "authorize";
                }
                else if(endpointKey == AuthorizationServerMetadataKeys.TokenEndpoint)
                {
                    suffix = "token";
                }
                else if(endpointKey == AuthorizationServerMetadataKeys.RevocationEndpoint)
                {
                    suffix = "revoke";
                }
                else if(endpointKey == AuthorizationServerMetadataKeys.IntrospectionEndpoint)
                {
                    suffix = "introspect";
                }
                else
                {
                    suffix = null;
                }

                if(suffix is null)
                {
                    return ValueTask.FromResult<Uri?>(null);
                }

                return ValueTask.FromResult<Uri?>(
                    new Uri($"{authority}/connect/{segment}/{suffix}"));
            },

            //Token classification for token-aware matchers (introspection,
            //revocation, userinfo, OID4VCI proof endpoints when those land).
            //The base scaffolding wires the JCose-side classifier; tests
            //that need custom classification (paseto, biscuit, deployment-
            //specific opaque shapes) replace this slot per test via
            //Server.Configuration. The OAuth-side delegate signature
            //includes RequestContext for applications that classify on
            //tenant data; the JCose classifier is purely structural and
            //does not consume context, so the wiring lambda discards it.
            ClassifyTokenAsync = (token, ctx, ct) =>
                JoseTokenClassifier.ClassifyAsync(
                    token,
                    TestSetup.Base64UrlDecoder,
                    static bytes => JsonSerializer.Deserialize<Dictionary<string, object>>(
                        bytes, TestSetup.DefaultSerializationOptions)
                        ?? throw new FormatException("Header JSON parsed to null."),
                    SensitiveMemoryPool<byte>.Shared,
                    ct),

            //Per-request policy resolution. The default dispatches on
            //ClientRecord.Profile across the three shipped profiles;
            //an unset Profile falls back to PolicyProfile.Fapi20
            //(FAPI 2.0 / HAIP-aligned).
            ResolvePolicyAsync = PolicyProfiles.DefaultResolvePolicyAsync,

            //Dynamic registration delegates. The parser uses JsonDocument to
            //read the few fields the canonical test exercises directly into a
            //ClientMetadata record; production deployments wire their full
            //JSON layer through Verifiable.OAuth.Json instead.
            ParseClientMetadataAsync = (body, ct) =>
            {
                using JsonDocument doc = JsonDocument.Parse(body);
                JsonElement root = doc.RootElement;

                List<Uri> redirectUris = [];
                if(root.TryGetProperty("redirect_uris", out JsonElement uris))
                {
                    foreach(JsonElement el in uris.EnumerateArray())
                    {
                        string? s = el.GetString();
                        if(s is not null)
                        {
                            redirectUris.Add(new Uri(s));
                        }
                    }
                }

                string? clientName = root.TryGetProperty("client_name", out JsonElement nm) ? nm.GetString() : null;
                string? scope = root.TryGetProperty("scope", out JsonElement sc) ? sc.GetString() : null;
                ClientAuthenticationMethod? authMethod = null;
                if(root.TryGetProperty("token_endpoint_auth_method", out JsonElement am)
                    && am.GetString() is string authMethodStr
                    && ClientAuthenticationMethodNames.TryParse(authMethodStr, out ClientAuthenticationMethod parsed))
                {
                    authMethod = parsed;
                }

                return ValueTask.FromResult(new ClientMetadata
                {
                    RedirectUris = redirectUris,
                    ClientName = clientName,
                    Scope = scope,
                    TokenEndpointAuthMethod = authMethod
                });
            },

            //Bearer-token validation for RFC 7592 management calls. Test
            //wiring stores the plaintext token and compares ordinally;
            //production deployments hash and use FixedTimeEquals.
            ValidateRegistrationAccessTokenAsync = (tenantId, clientId, presented, _, _) =>
                ValueTask.FromResult(
                    RegistrationAccessTokens.TryGetValue(clientId, out string? stored)
                    && string.Equals(stored, presented, StringComparison.Ordinal))
        };

        AuthorizationServerCryptography cryptography = new()
        {
            SigningKeyResolver = (keyId, ctx, ct) =>
                ValueTask.FromResult(
                    SigningKeys.TryGetValue(keyId, out PrivateKeyMemory? key)
                        ? key : null),

            VerificationKeyResolver = (keyId, ctx, ct) =>
                ValueTask.FromResult(
                    VerificationKeys.TryGetValue(keyId, out PublicKeyMemory? key)
                        ? key : null),

            DecryptionKeyResolver = (keyId, ctx, ct) =>
                ValueTask.FromResult(
                    DecryptionKeys.TryGetValue(keyId, out PrivateKeyMemory? key)
                        ? key : null),

            BuildJwksDocumentAsync = (registration, ctx, ct) =>
            {
                List<JsonWebKey> jwks = [];

                foreach(SigningKeySet set in registration.SigningKeys.Values)
                {
                    foreach(KeyId publishedKeyId in set.PublishedKeys)
                    {
                        if(!VerificationKeys.TryGetValue(publishedKeyId, out PublicKeyMemory? publicKey))
                        {
                            continue;
                        }

                        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
                            publicKey.Tag.Get<CryptoAlgorithm>(),
                            publicKey.Tag.Get<Purpose>(),
                            publicKey.AsReadOnlySpan(),
                            TestSetup.Base64UrlEncoder);
                        jwk.Kid = publishedKeyId.Value;
                        jwk.Use = WellKnownJwkValues.UseSig;

                        jwks.Add(jwk);
                    }
                }

                return ValueTask.FromResult(new JwksDocument { Keys = [.. jwks] });
            }
        };

        AuthorizationServerCodecs codecs = new()
        {
            Encoder = TestSetup.Base64UrlEncoder,
            Decoder = TestSetup.Base64UrlDecoder,
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigestAsync,

            //The library signs access tokens via the registered token producers.
            //TestHostShell supplies the two JSON serialization delegates; tests
            //that need non-standard signing assign their own producers per test.
            JwtHeaderSerializer = static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            JwtPayloadSerializer = static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions),

            //Deserializers required by JAR-bearing matchers (AuthCode JAR-PAR
            //and AuthCode JAR-by-value direct Authorize). Other in-dispatch
            //consumers may follow; the slots are wired here once.
            JwtHeaderDeserializer = static bytes =>
                JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                    bytes, TestSetup.DefaultSerializationOptions)
                ?? throw new FormatException("Header JSON parsed to null."),
            JwtPayloadDeserializer = static bytes =>
                JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                    bytes, TestSetup.DefaultSerializationOptions)
                ?? throw new FormatException("Payload JSON parsed to null.")
        };

        Server = new AuthorizationServer
        {
            Integration = integration,
            Cryptography = cryptography,
            Codecs = codecs,
            TimeProvider = timeProvider,

            //The fold pipeline is configured up-front via ServerConfiguration.
            //TestHostShell wires the three library-shipped endpoint builders and
            //leaves token producers and claim contributors empty; tests that need
            //custom producers or contributors apply a new ServerConfiguration via
            //Server.ApplyConfiguration before dispatching.
            Configuration = new ServerConfiguration
            {
                EndpointBuilders = new EndpointBuilderSet(
                [
                    AuthCodeEndpoints.Builder,
                    Oid4VpEndpoints.Builder,
                    MetadataEndpoints.Builder,
                    RegistrationEndpoints.Builder
                ]),
                TokenProducers = TokenProducerSet.Empty,
                ClaimContributors = ClaimContributorSet.Empty
            },

            //The HAIP executor handles OID4VP flows (SignJar, DecryptResponse).
            //Auth Code flows do not produce actions and ignore the executor.
            //Key resolvers are read from the server's groups at call time, not
            //captured here.
            ActionExecutor = HaipOid4VpVerifierExecutor.Create(
                headerSerializer: header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                    (Dictionary<string, object>)header,
                    TestSetup.DefaultSerializationOptions),
                payloadSerializer: payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                    (Dictionary<string, object>)payload,
                    TestSetup.DefaultSerializationOptions),
                dcqlQuerySerializer: q =>
                    JsonSerializer.Serialize(q, TestSetup.DefaultSerializationOptions),
                clientMetadataSerializer: m =>
                    JsonSerializer.Serialize(m, TestSetup.DefaultSerializationOptions),
                decoder: TestSetup.Base64UrlDecoder,
                encoder: TestSetup.Base64UrlEncoder,
                resolveIssuerKey: resolveIssuerKey,
                parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                    s, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared, TestSalts.TestSaltTag),
                computeSdJwtHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(
                    t, TestSetup.Base64UrlEncoder),
                computeDigest: MicrosoftEntropyFunctions.ComputeDigestAsync,
                vpValidator: vpValidator,
                keyAgreementDecryptDelegate:
                    BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                keyDerivationDelegate: ConcatKdf.DefaultKeyDerivationDelegate,
                aeadDecryptDelegate: BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                pool: SensitiveMemoryPool<byte>.Shared)
        };

        Server.Validate();

        //Subscribe to populate the routing table from events.
        Server.Events.Subscribe(new RegistrationObserver(Registrations, RegistrationAccessTokens));
    }


    /// <summary>
    /// Registers a client with the specified capabilities and fresh P-256 key material.
    /// </summary>
    /// <param name="clientId">The OAuth client identifier.</param>
    /// <param name="baseUri">The base URI for the client's endpoints.</param>
    /// <param name="capabilities">
    /// The capabilities this client is allowed to use. Determines which endpoints
    /// are active.
    /// </param>
    public VerifierKeyMaterial RegisterClient(
        string clientId,
        Uri baseUri,
        ImmutableHashSet<ServerCapabilityName> capabilities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);
        ArgumentNullException.ThrowIfNull(capabilities);

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        KeyId encryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeyPair =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();

        SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;
        DecryptionKeys[encryptionKeyId] = exchangeKeyPair.PrivateKey;

        VerifierClientMetadata? clientMetadata = capabilities.Contains(
            ServerCapabilityName.VerifiablePresentation)
            ? BuildClientMetadata(clientId, exchangeKeyPair.PublicKey, encryptionKeyId)
            : null;

        Uri responseUri = new(baseUri, ServerEndpointPaths.DirectPost
            .Replace("{segment}", segment, StringComparison.Ordinal));

        ClientRecord registration = new()
        {
            ClientId = clientId,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/callback")),
            AllowedScopes = ImmutableHashSet.Create(WellKnownScopes.OpenId),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.JarSigning, new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            ResponseUri = responseUri,
            ClientMetadata = clientMetadata
        };

        //Index by both segment and clientId for lookup.
        Registrations[segment] = registration;
        Registrations[clientId] = registration;

        //Emit event so observers (routing table, caches) are notified.
        Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new RequestContext());

        //Dispose the exchange public key — only the private key is retained.
        //The signing public key is retained in VerificationKeys for JAR verification.
        exchangeKeyPair.PublicKey.Dispose();

        return new VerifierKeyMaterial(
            registration,
            signingKeyPair.PublicKey,
            signingKeyPair.PrivateKey,
            exchangeKeyPair.PrivateKey,
            encryptionKeyId,
            signingKeyId);
    }


    /// <summary>
    /// Registers a client with externally provided signing key material.
    /// Use this overload to test JWKS output for any algorithm — P-256, P-384,
    /// P-521, Ed25519, secp256k1, RSA-2048, ML-DSA-44, ML-DSA-65, ML-DSA-87.
    /// </summary>
    /// <param name="clientId">The client identifier.</param>
    /// <param name="signingKeyPair">
    /// The signing key pair. Ownership transfers to the host — both keys are
    /// stored in the key stores and disposed when the host is disposed.
    /// </param>
    /// <param name="capabilities">
    /// The capabilities this client is allowed to use.
    /// </param>
    /// <returns>The registered <see cref="ClientRecord"/>.</returns>
    /// <summary>
    /// Registers a client with the supplied signing key in the
    /// <see cref="KeyUsageContext.JarSigning"/> slot, so JAR-bearing AuthCode
    /// or OID4VP flows can be parameterised across signature algorithms.
    /// </summary>
    public VerifierKeyMaterial RegisterJarSigningClient(
        string clientId,
        Uri baseUri,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair,
        ImmutableHashSet<ServerCapabilityName> capabilities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);
        ArgumentNullException.ThrowIfNull(signingKeyPair);
        ArgumentNullException.ThrowIfNull(capabilities);

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;

        //P-256 exchange keypair satisfies VerifierKeyMaterial's required
        //DecryptionPrivateKey slot. JAR-signing-only tests do not exercise
        //response encryption, but the type's invariant still applies.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeyPair =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        KeyId encryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        DecryptionKeys[encryptionKeyId] = exchangeKeyPair.PrivateKey;
        exchangeKeyPair.PublicKey.Dispose();

        ClientRecord registration = new()
        {
            ClientId = clientId,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/callback")),
            AllowedScopes = ImmutableHashSet.Create(WellKnownScopes.OpenId),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.JarSigning, new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            ResponseUri = new Uri(baseUri, ServerEndpointPaths.DirectPost
                .Replace("{segment}", segment, StringComparison.Ordinal))
        };

        Registrations[segment] = registration;
        Registrations[clientId] = registration;

        Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new RequestContext());

        return new VerifierKeyMaterial(
            registration,
            signingKeyPair.PublicKey,
            signingKeyPair.PrivateKey,
            decryptionPrivateKey: exchangeKeyPair.PrivateKey,
            encryptionKeyId: encryptionKeyId,
            signingKeyId: signingKeyId);
    }


    public ClientRecord RegisterSigningClient(
        string clientId,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair,
        ImmutableHashSet<ServerCapabilityName> capabilities)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(signingKeyPair);
        ArgumentNullException.ThrowIfNull(capabilities);

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;

        ClientRecord registration = new()
        {
            ClientId = clientId,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/callback")),
            AllowedScopes = ImmutableHashSet.Create(WellKnownScopes.OpenId),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.AccessTokenIssuance, new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty
        };

        Registrations[segment] = registration;
        Registrations[clientId] = registration;

        Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new RequestContext());

        return registration;
    }


    /// <summary>
    /// Constructs an <see cref="OAuthClient"/> over a fresh
    /// <see cref="OAuthClientInfrastructure"/> and the matching
    /// <see cref="ClientRegistration"/> for the registered tenant. Returns
    /// both because every protocol-method call threads the registration
    /// alongside the client.
    /// </summary>
    /// <param name="record">The server-side registration record.</param>
    /// <param name="redirectUri">The client's redirect URI.</param>
    /// <param name="issuerUri">The expected issuer URI for callback validation.</param>
    public (OAuthClient Client, ClientRegistration Registration) CreateOAuthClientAndRegistration(
        ClientRecord record,
        string redirectUri,
        string issuerUri)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerUri);

        InProcessTransport transport = new(
            Server, record, record.TenantId, issuerUri);

        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        string segment = record.TenantId.Value;
        Uri baseUri = new("https://verifier.example.com");

        Uri parEndpoint = new(baseUri, ServerEndpointPaths.Par
            .Replace("{segment}", segment, StringComparison.Ordinal));
        Uri authEndpoint = new(baseUri, ServerEndpointPaths.Authorize
            .Replace("{segment}", segment, StringComparison.Ordinal));
        Uri tokenEndpoint = new(baseUri, ServerEndpointPaths.Token
            .Replace("{segment}", segment, StringComparison.Ordinal));
        Uri issuerUriValue = new(issuerUri);

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUriValue,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: transport.SendAsync,
            saveStateAsync: (state, ct) =>
            {
                clientFlowStore[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, ct) =>
            {
                foreach(OAuthFlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<OAuthFlowState?>(state);
                    }
                }

                return ValueTask.FromResult<OAuthFlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test host pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("Phase 2 does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: Time);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(record.ClientId),
            AuthorizationServerIssuer = issuerUriValue,
            RedirectUris = [new Uri(redirectUri)],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Haip10
        };

        return (new OAuthClient(infrastructure), registration);
    }


    /// <summary>
    /// Constructs an <see cref="OAuthClient"/> with the full dynamic-registration
    /// + AuthCode transport wired but without any pre-existing
    /// <see cref="ClientRegistration"/>. Used by the canonical phase 4 test
    /// that registers dynamically and then drives an AuthCode flow against
    /// the freshly-issued registration.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The infrastructure wires three transports:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     <c>SendJsonPostAsync</c> — dispatches the RFC 7591 §3 POST to
    ///     <see cref="RegistrationEndpoints.HandleCreateAsync"/> with the
    ///     <see cref="DynamicRegistrationTenant"/> as the tenant identifier.
    ///   </description></item>
    ///   <item><description>
    ///     <c>SendFormPostAsync</c> — dispatches PAR / token / revocation
    ///     calls via a tenant-lookup transport that reads the segment from
    ///     the URL and resolves the <see cref="ClientRecord"/> from
    ///     <see cref="Registrations"/>.
    ///   </description></item>
    ///   <item><description>
    ///     <c>ResolveAuthorizationServerMetadataAsync</c> — returns AS
    ///     metadata whose endpoints point at the test verifier's hostnames
    ///     for the configured tenant segment.
    ///   </description></item>
    /// </list>
    /// </remarks>
    public OAuthClient CreateOAuthClientWithoutRegistration()
    {
        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        Uri baseUri = new("https://verifier.example.com");
        Uri parEndpoint = new(baseUri, ServerEndpointPaths.Par
            .Replace("{segment}", DynamicRegistrationTenant, StringComparison.Ordinal));
        Uri authEndpoint = new(baseUri, ServerEndpointPaths.Authorize
            .Replace("{segment}", DynamicRegistrationTenant, StringComparison.Ordinal));
        Uri tokenEndpoint = new(baseUri, ServerEndpointPaths.Token
            .Replace("{segment}", DynamicRegistrationTenant, StringComparison.Ordinal));

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = IssuerUri,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint
        };

        LookupTransport transport = new(Server, Registrations, IssuerUri.OriginalString);

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: transport.SendAsync,
            saveStateAsync: (state, ct) =>
            {
                clientFlowStore[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, ct) =>
            {
                foreach(OAuthFlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<OAuthFlowState?>(state);
                    }
                }

                return ValueTask.FromResult<OAuthFlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test host pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) => ParseRegistrationResponseJson(body),
            resolveAuthorizationServerMetadataAsync: (issuer, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: Time,
            sendJsonPostAsync: async (endpoint, jsonBody, headers, cancellationToken) =>
            {
                //Headers are unused for the global registration POST — RFC 7591 §3 is unauthenticated.
                _ = headers;
                TenantId tenantId = new(DynamicRegistrationTenant);
                ImmutableHashSet<ServerCapabilityName> capabilities = ImmutableHashSet.Create(
                    ServerCapabilityName.AuthorizationCode,
                    ServerCapabilityName.PushedAuthorization,
                    ServerCapabilityName.DynamicClientRegistration);

                ServerHttpResponse response = await RegistrationEndpoints.HandleCreateAsync(
                    tenantId,
                    jsonBody,
                    capabilities,
                    new RequestContext(),
                    Server,
                    cancellationToken).ConfigureAwait(false);

                return new HttpResponseData
                {
                    Body = response.Body ?? string.Empty,
                    StatusCode = response.StatusCode
                };
            },
            sendJsonGetAsync: (endpoint, headers, ct) =>
                DispatchManagementAsync(endpoint, headers, WellKnownHttpMethods.Get, jsonBody: null, ct),
            sendJsonPutAsync: (endpoint, jsonBody, headers, ct) =>
                DispatchManagementAsync(endpoint, headers, WellKnownHttpMethods.Put, jsonBody: jsonBody, ct),
            sendJsonDeleteAsync: (endpoint, headers, ct) =>
                DispatchManagementAsync(endpoint, headers, WellKnownHttpMethods.Delete, jsonBody: null, ct),
            parseClientMetadataAsync: ParseClientMetadataJson);

        return new OAuthClient(infrastructure);
    }


    /// <summary>
    /// Test-transport dispatcher for the three RFC 7592 management methods.
    /// Resolves the registration by tenant segment from the URL path, builds
    /// an <see cref="IncomingRequest"/> carrying the Authorization header
    /// (and the request body for PUT), then dispatches via
    /// <see cref="AuthorizationServer.DispatchAsync"/>.
    /// </summary>
    private async ValueTask<HttpResponseData> DispatchManagementAsync(
        Uri endpoint,
        OutgoingHeaders headers,
        string method,
        string? jsonBody,
        CancellationToken cancellationToken)
    {
        string path = endpoint.IsAbsoluteUri ? endpoint.AbsolutePath : endpoint.OriginalString;

        string segment = LookupTransport.ExtractTenantSegmentForTests(path);
        if(!Registrations.TryGetValue(segment, out ClientRecord? registration))
        {
            return new HttpResponseData
            {
                StatusCode = 404,
                Body = $"No registration found for segment '{segment}'."
            };
        }

        Dictionary<string, string[]> headerDict = new(StringComparer.OrdinalIgnoreCase);
        foreach(KeyValuePair<string, string> pair in headers.Values)
        {
            headerDict[pair.Key] = [pair.Value];
        }
        RequestHeaders requestHeaders = new(headerDict);

        RequestBody body = jsonBody is null
            ? RequestBody.None
            : new RequestBody
            {
                Bytes = Encoding.UTF8.GetBytes(jsonBody),
                ContentType = WellKnownMediaTypes.Application.Json
            };

        IncomingRequest request = new(
            Path: path,
            Method: method,
            Fields: new RequestFields(new Dictionary<string, string>(0)),
            Headers: requestHeaders,
            RouteValues: RouteValues.Empty)
        {
            Body = body
        };

        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(IssuerUri);
        context.SetRegistration(registration);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        return new HttpResponseData
        {
            Body = response.Body ?? string.Empty,
            StatusCode = response.StatusCode
        };
    }


    /// <summary>
    /// Minimal client-side <see cref="ClientMetadata"/> parser used by the
    /// test transport. Reads only the fields the canonical lifecycle test
    /// exercises (<c>client_id</c>, <c>redirect_uris</c>, <c>scope</c>,
    /// <c>client_name</c>); production wiring uses
    /// <c>Verifiable.OAuth.Json</c>.
    /// </summary>
    private static ValueTask<ClientMetadata> ParseClientMetadataJson(string body, CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        List<Uri> redirectUris = [];
        if(root.TryGetProperty("redirect_uris", out JsonElement uris))
        {
            foreach(JsonElement el in uris.EnumerateArray())
            {
                string? s = el.GetString();
                if(s is not null)
                {
                    redirectUris.Add(new Uri(s));
                }
            }
        }

        string? clientName = root.TryGetProperty("client_name", out JsonElement nm) ? nm.GetString() : null;
        string? scope = root.TryGetProperty("scope", out JsonElement sc) ? sc.GetString() : null;

        return ValueTask.FromResult(new ClientMetadata
        {
            ClientName = clientName,
            RedirectUris = redirectUris,
            Scope = scope
        });
    }


    private static ValueTask<RegistrationResponse> ParseRegistrationResponseJson(string body)
    {
        using JsonDocument doc = JsonDocument.Parse(body);
        JsonElement root = doc.RootElement;

        string clientIdValue = root.GetProperty("client_id").GetString()
            ?? throw new FormatException("RFC 7591 §3.2.1 response missing client_id.");

        RegistrationAccessToken? token = null;
        if(root.TryGetProperty("registration_access_token", out JsonElement tokElem)
            && tokElem.GetString() is string tokenValue)
        {
            token = new RegistrationAccessToken(tokenValue);
        }

        Uri? mgmtUri = null;
        if(root.TryGetProperty("registration_client_uri", out JsonElement mgmtElem)
            && mgmtElem.GetString() is string mgmtValue
            && Uri.TryCreate(mgmtValue, UriKind.RelativeOrAbsolute, out Uri? parsedMgmt))
        {
            mgmtUri = parsedMgmt;
        }

        DateTimeOffset? issuedAt = null;
        if(root.TryGetProperty("client_id_issued_at", out JsonElement issuedElem)
            && issuedElem.TryGetInt64(out long unixIssued))
        {
            issuedAt = DateTimeOffset.FromUnixTimeSeconds(unixIssued);
        }

        ClientMetadata metadata = new()
        {
            ClientName = root.TryGetProperty("client_name", out JsonElement nm) ? nm.GetString() : null,
            Scope = root.TryGetProperty("scope", out JsonElement sc) ? sc.GetString() : null
        };

        return ValueTask.FromResult(new RegistrationResponse
        {
            ClientId = new ClientId(clientIdValue),
            Metadata = metadata,
            AccessToken = token,
            ManagementUri = mgmtUri,
            IssuedAt = issuedAt
        });
    }


    /// <summary>
    /// Creates a <see cref="TestWallet"/> for OID4VP flows.
    /// </summary>
    /// <param name="expectedVerifierClientId">
    /// The Verifier client identifier the Wallet expects in every JAR.
    /// </param>
    /// <param name="credentials">
    /// Map from credential identifier to serialized SD-JWT string.
    /// </param>
    /// <param name="holderPrivateKey">
    /// The holder's private key for KB-JWT signing.
    /// </param>
    public TestWallet CreateWallet(
        string expectedVerifierClientId,
        Dictionary<string, string> credentials,
        PrivateKeyMemory holderPrivateKey)
    {
        return new TestWallet(expectedVerifierClientId, credentials, holderPrivateKey, Time);
    }


    /// <summary>
    /// Resolves the endpoint chain for a registration in the supplied
    /// per-request context. Tests that don't have a meaningful context to
    /// thread (structural inspection, capability listing, no actual request
    /// in flight) construct a fresh empty <see cref="RequestContext"/> at
    /// the call site.
    /// </summary>
    public EndpointChain GetEndpoints(ClientRecord registration, RequestContext context)
        => Server.GetEndpoints(registration, context);


    /// <summary>
    /// Returns the current server-side flow state. Resolves external handles
    /// (request_uri tokens, codes) through the secondary indexes, so tests
    /// can look up state using whatever handle they have.
    /// </summary>
    public (OAuthFlowState State, int StepCount) GetFlowState(string key)
    {
        if(FlowStates.TryGetValue(key, out var entry))
        {
            return entry;
        }

        if(RequestUriTokenIndex.TryGetValue(key, out string? flowId)
            && FlowStates.TryGetValue(flowId, out entry))
        {
            return entry;
        }

        if(CodeIndex.TryGetValue(key, out flowId)
            && FlowStates.TryGetValue(flowId, out entry))
        {
            return entry;
        }

        throw new KeyNotFoundException($"No flow found for key '{key}'.");
    }


    /// <summary>
    /// OID4VP PAR — creates a new Verifiable Presentation flow.
    /// Returns the request URI (for QR code) and the per-flow handle (for
    /// subsequent JAR and direct_post steps). The internal flow identifier
    /// never leaves this method.
    /// </summary>
    public async Task<(Uri RequestUri, string ParHandle)> HandleParAsync(
        VerifierKeyMaterial keyMaterial,
        TransactionNonce nonce,
        PreparedDcqlQuery dcqlQuery,
        CancellationToken cancellationToken)
    {
        RequestContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetTransactionNonce(nonce);
        context.SetPreparedQuery(dcqlQuery);
        context.SetDecryptionKeyId(keyMaterial.EncryptionKeyId);

        //OID4VP PAR is invoked internally by the verifier app — not from a
        //wire HTTP request. The matcher reads context (TransactionNonce,
        //PreparedQuery, DecryptionKeyId) and ignores path and fields.
        //IncomingRequest is constructed for protocol-uniformity but its
        //Path is the canonical /par template substituted with the segment;
        //a real verifier deployment that exposed this endpoint internally
        //would do the same.
        string segment = keyMaterial.Registration.TenantId.Value;
        string parPath = ServerEndpointPaths.Par.Replace("{segment}", segment, StringComparison.Ordinal);

        IncomingRequest request = new(
            Path: parPath,
            Method: "POST",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"PAR failed with status {response.StatusCode}: {response.Body}");
        }

        //The library placed the per-flow handle on context before invoking
        //ResolveEndpointUriAsync; it is still on context after dispatch returns.
        string parHandle = context.ParHandle
            ?? throw new InvalidOperationException("ParHandle not set after PAR.");
        Uri requestUri = context.GeneratedRequestUri
            ?? throw new InvalidOperationException("GeneratedRequestUri not set after PAR.");

        return (requestUri, parHandle);
    }


    /// <summary>
    /// OID4VP JAR request — fetches the signed JAR for a continuing flow.
    /// The <paramref name="externalToken"/> is the opaque token from
    /// <see cref="HandleParAsync"/>, not the internal flow identifier.
    /// </summary>
    public async Task<string> HandleJarRequestAsync(
        VerifierKeyMaterial keyMaterial,
        string externalToken,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(externalToken);

        RequestContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetCorrelationKey(externalToken);

        //JAR Request matches on context.CorrelationKey — the verifier app's
        //URL routing layer extracted the {flowId} segment from the JAR URL
        //and placed it on context before dispatching.
        string segment = keyMaterial.Registration.TenantId.Value;
        string jarPath = ServerEndpointPaths.JarRequest
            .Replace("{segment}", segment, StringComparison.Ordinal)
            .Replace("{flowId}", externalToken, StringComparison.Ordinal);

        IncomingRequest request = new(
            Path: jarPath,
            Method: "GET",
            Fields: new RequestFields(),
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"JAR request failed with status {response.StatusCode}: {response.Body}");
        }

        return context.Jar
            ?? throw new InvalidOperationException("JAR not set in context after dispatch.");
    }


    /// <summary>
    /// OID4VP direct_post — posts the encrypted VP token response.
    /// The <paramref name="externalToken"/> is the opaque token from
    /// <see cref="HandleParAsync"/>, not the internal flow identifier.
    /// </summary>
    public async Task<PresentationVerifiedState> HandleDirectPostAsync(
        VerifierKeyMaterial keyMaterial,
        string externalToken,
        string compactJwe,
        Uri? redirectUri,
        CancellationToken cancellationToken)
    {
        RequestContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);

        if(redirectUri is not null)
        {
            context.SetOid4VpRedirectUri(redirectUri);
        }

        RequestFields fields = new()
        {
            [OAuthRequestParameters.Response] = compactJwe,
            [OAuthRequestParameters.State] = externalToken
        };

        string segment = keyMaterial.Registration.TenantId.Value;
        string directPostPath = ServerEndpointPaths.DirectPost
            .Replace("{segment}", segment, StringComparison.Ordinal);

        IncomingRequest request = new(
            Path: directPostPath,
            Method: "POST",
            Fields: fields,
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        ServerHttpResponse response = await Server.DispatchAsync(
            request, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"direct_post failed with status {response.StatusCode}: {response.Body}");
        }

        return (PresentationVerifiedState)GetFlowState(externalToken).State;
    }


    /// <summary>
    /// Dispatches a pre-built <see cref="IncomingRequest"/> for the given
    /// segment. Used by tests that need to verify negative-path behaviour
    /// (404 after deregistration, malformed requests, etc.) — the request
    /// shape is the test's responsibility.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchBySegmentAsync(
        string segment,
        IncomingRequest request,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Test-side convenience: dispatches a request at the given
    /// <paramref name="pathTemplate"/> for <paramref name="segment"/>, building
    /// the <see cref="IncomingRequest"/> from the template (with
    /// <c>{segment}</c> substituted), the supplied HTTP method, and fields.
    /// Tests pass <see cref="ServerEndpointPaths"/> constants directly.
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchAtPathAsync(
        string segment,
        string pathTemplate,
        string httpMethod,
        RequestFields fields,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(pathTemplate);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(context);

        string concretePath = pathTemplate.Replace("{segment}", segment, StringComparison.Ordinal);

        IncomingRequest request = new(
            Path: concretePath,
            Method: httpMethod,
            Fields: fields,
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        context.SetTenantId(segment);
        return await Server.DispatchAsync(request, context, cancellationToken)
            .ConfigureAwait(false);
    }


    /// <summary>
    /// Deregisters a client by endpoint segment and emits a
    /// <see cref="ClientDeregistered"/> event.
    /// </summary>
    public void DeregisterClient(string segment, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        if(!Registrations.TryGetValue(segment, out ClientRecord? registration))
        {
            return;
        }

        Server.DeregisterClient(registration, reason, new RequestContext());
    }


    /// <summary>
    /// Rotates the signing key for a registered client, emits a
    /// <see cref="ClientUpdated"/> event, and returns the new key material.
    /// </summary>
    /// <remarks>
    /// The old signing key remains in the key store so in-flight flows that were
    /// signed with it can still be verified.
    /// </remarks>
    public VerifierKeyMaterial RotateSigningKey(string segment)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);

        if(!Registrations.TryGetValue(segment, out ClientRecord? previous))
        {
            throw new InvalidOperationException(
                $"No registration found for segment '{segment}'.");
        }

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> newSigningKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> newExchangeKeys =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();

        KeyId newSigningKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        KeyId newEncryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        SigningKeys[newSigningKeyId] = newSigningKeys.PrivateKey;
        VerificationKeys[newSigningKeyId] = newSigningKeys.PublicKey;
        DecryptionKeys[newEncryptionKeyId] = newExchangeKeys.PrivateKey;

        string jwksJson = EphemeralEncryptionKeyPair.CreatePublicKeyJwks(
            newExchangeKeys.PublicKey,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        newExchangeKeys.PublicKey.Dispose();

        VerifierClientMetadata newMetadata =
            HaipProfile.CreateVerifierClientMetadata(previous.ClientId, jwksJson);

        ImmutableDictionary<KeyUsageContext, SigningKeySet>.Builder signingKeysBuilder =
            ImmutableDictionary.CreateBuilder<KeyUsageContext, SigningKeySet>();
        foreach(KeyValuePair<KeyUsageContext, SigningKeySet> entry in previous.SigningKeys)
        {
            signingKeysBuilder[entry.Key] = entry.Value;
        }
        signingKeysBuilder[KeyUsageContext.JarSigning] =
            new SigningKeySet { Current = [newSigningKeyId] };

        ClientRecord updated = previous with
        {
            SigningKeys = signingKeysBuilder.ToImmutable(),
            ClientMetadata = newMetadata
        };

        //Update the routing table directly — the observer also handles this
        //via the ClientUpdated event, but explicit update ensures consistency.
        Registrations[segment] = updated;

        Server.UpdateClient(previous, updated, new RequestContext());

        return new VerifierKeyMaterial(
            updated,
            newSigningKeys.PublicKey,
            newSigningKeys.PrivateKey,
            newExchangeKeys.PrivateKey,
            newEncryptionKeyId,
            newSigningKeyId);
    }


    /// <summary>
    /// Generates a fresh P-256 signing key pair, stores it under a new <see cref="KeyId"/>,
    /// and returns that identifier. Does not modify any registration — the caller
    /// decides which rotation slot the new key enters and calls
    /// <see cref="UpdateSigningKeys"/> to apply the change.
    /// </summary>
    /// <remarks>
    /// Used by rotation tests that need fine-grained control over which slot a new
    /// key lands in (Incoming, Current, Retiring, Historical). The more coarse
    /// <see cref="RotateSigningKey"/> allocates and installs in a single step.
    /// </remarks>
    public KeyId AllocateSigningKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> fresh =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        KeyId newKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        SigningKeys[newKeyId] = fresh.PrivateKey;
        VerificationKeys[newKeyId] = fresh.PublicKey;

        return newKeyId;
    }


    /// <summary>
    /// Replaces the <see cref="ClientRecord.SigningKeys"/> map for the given
    /// segment, then re-publishes the updated registration through the server's
    /// <see cref="AuthorizationServer.UpdateClient"/> so a <c>ClientUpdated</c>
    /// event is emitted. Used by rotation tests to inject Incoming, Retiring,
    /// and Historical slot configurations without going through the full
    /// <see cref="RotateSigningKey"/> path.
    /// </summary>
    /// <param name="segment">The endpoint segment identifying the registration to update.</param>
    /// <param name="signingKeys">The complete <see cref="SigningKeySet"/> map replacing the current one.</param>
    public void UpdateSigningKeys(
        string segment,
        IReadOnlyDictionary<KeyUsageContext, SigningKeySet> signingKeys)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentNullException.ThrowIfNull(signingKeys);

        if(!Registrations.TryGetValue(segment, out ClientRecord? previous))
        {
            throw new InvalidOperationException(
                $"No registration found for segment '{segment}'.");
        }

        ClientRecord updated = previous with
        {
            SigningKeys = signingKeys.ToImmutableDictionary()
        };

        Registrations[segment] = updated;
        Server.UpdateClient(previous, updated, new RequestContext());
    }


    /// <summary>
    /// Registers a client whose policy profile requires DPoP — HAIP 1.0 by
    /// default. Allows AuthorizationCode + PushedAuthorization capabilities so
    /// the canonical token-endpoint DPoP enforcement path is reachable.
    /// </summary>
    public VerifierKeyMaterial RegisterDpopClient(
        string clientId,
        Uri baseUri,
        PolicyProfile? profile = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(baseUri);

        ImmutableHashSet<ServerCapabilityName> capabilities = ImmutableHashSet.Create(
            ServerCapabilityName.AuthorizationCode,
            ServerCapabilityName.PushedAuthorization);

        string segment = Guid.NewGuid().ToString("N")[..8];
        KeyId signingKeyId = new($"urn:uuid:{Guid.NewGuid()}");

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> signingKeyPair =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        SigningKeys[signingKeyId] = signingKeyPair.PrivateKey;
        VerificationKeys[signingKeyId] = signingKeyPair.PublicKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> exchangeKeyPair =
            TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        KeyId encryptionKeyId = new($"urn:uuid:{Guid.NewGuid()}");
        DecryptionKeys[encryptionKeyId] = exchangeKeyPair.PrivateKey;
        exchangeKeyPair.PublicKey.Dispose();

        ClientRecord registration = new()
        {
            ClientId = clientId,
            TenantId = segment,
            IssuerUri = new Uri($"https://issuer.test/{segment}"),
            AllowedCapabilities = capabilities,
            AllowedRedirectUris = ImmutableHashSet.Create(
                new Uri("https://client.example.com/callback")),
            AllowedScopes = ImmutableHashSet.Create(WellKnownScopes.OpenId),
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.AccessTokenIssuance,
                    new SigningKeySet { Current = [signingKeyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty,
            //FAPI 2.0 / HAIP require a resolved aud on access tokens. Map the
            //openid scope to a deterministic resource-server identifier so the
            //RFC 9068 producer has an audience to embed.
            ScopeToAudience = new Dictionary<string, IReadOnlyList<string>>
            {
                [WellKnownScopes.OpenId] = new[] { "https://rs.example.com" }
            },
            Profile = profile ?? PolicyProfile.Haip10
        };

        Registrations[segment] = registration;
        Registrations[clientId] = registration;

        Server.RegisterClient(
            registration,
            new RegistrationAccessToken(Guid.NewGuid().ToString("N")),
            new RequestContext());

        return new VerifierKeyMaterial(
            registration,
            signingKeyPair.PublicKey,
            signingKeyPair.PrivateKey,
            decryptionPrivateKey: exchangeKeyPair.PrivateKey,
            encryptionKeyId: encryptionKeyId,
            signingKeyId: signingKeyId);
    }


    /// <summary>
    /// Wires up the AS-side DPoP delegates on the server's integration:
    /// HMAC-key resolver, nonce issuance, nonce validation, and proof
    /// validation. Returns the in-process HMAC resolver so tests can drive
    /// rotation. Idempotent — repeat calls reuse the existing resolver.
    /// </summary>
    public InProcessHmacKeyResolver EnableDpop(string initialKid = "test-hmac-1")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(initialKid);

        if(DpopHmacResolver is not null)
        {
            return DpopHmacResolver;
        }

        SymmetricKey hmacKey = CreateFreshHmacKey(initialKid);
        DpopHmacResolver = new InProcessHmacKeyResolver(hmacKey, initialKid);

        Server.Integration.ResolveServerHmacKeyAsync = DpopHmacResolver.ResolveAsync;
        Server.Integration.ValidateDpopProofAsync = (request, ct) =>
            DpopProofValidation.ValidateAsync(
                request,
                MicrosoftCryptographicFunctions.VerifyP256Async,
                DpopTestSupport.Parser,
                Base64UrlEncoder,
                Base64UrlDecoder,
                Time,
                MemoryPool,
                iatSkew: WellKnownDpopValues.DefaultIatSkew,
                cancellationToken: ct);
        Server.Integration.IssueDpopNonceAsync = (audience, tenantId, ctx, ct) =>
            DefaultDpopNonceIssuance.IssueAsync(
                audience,
                tenantId,
                ctx,
                DpopHmacResolver.ResolveAsync,
                Time,
                Base64UrlEncoder,
                MemoryPool,
                ct);
        Server.Integration.ValidateDpopNonceAsync = (presented, audience, tenantId, ctx, ct) =>
            DefaultDpopNonceValidation.ValidateAsync(
                presented,
                audience,
                tenantId,
                ctx,
                DpopHmacResolver.ResolveAsync,
                Time,
                WellKnownDpopValues.DefaultNonceValidityWindow,
                Base64UrlDecoder,
                MemoryPool,
                ct);

        return DpopHmacResolver;
    }


    /// <summary>
    /// Rotates the AS-side HMAC key used to sign nonces. Returns the new key's
    /// kid. <see cref="EnableDpop"/> must have been called first.
    /// </summary>
    public string RotateDpopHmacKey(string newKid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(newKid);
        if(DpopHmacResolver is null)
        {
            throw new InvalidOperationException(
                "EnableDpop must be called before RotateDpopHmacKey.");
        }

        SymmetricKey newKey = CreateFreshHmacKey(newKid);
        DpopHmacResolver.Rotate(newKey, newKid);
        return newKid;
    }


    /// <summary>
    /// Mints a fresh 256-bit HMAC-SHA-256 key and wires it for the bound
    /// HMAC delegates registered globally by <see cref="TestSetup"/>.
    /// Records the key for lifetime cleanup at host disposal.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "SymmetricKeyMemory ownership transfers to SymmetricKey; SymmetricKey itself is tracked in DpopOwnedDisposables and disposed when the host is disposed.")]
    private SymmetricKey CreateFreshHmacKey(string id)
    {
        IMemoryOwner<byte> owner = SensitiveMemoryPool<byte>.Shared.Rent(32);
        SymmetricKeyMemory material;
        try
        {
            RandomNumberGenerator.Fill(owner.Memory.Span[..32]);
            material = new SymmetricKeyMemory(owner, CryptoTags.HmacSha256Key);
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        SymmetricKey key = new(
            material,
            id,
            MicrosoftHmacFunctions.ComputeHmacAsync,
            MicrosoftHmacFunctions.VerifyHmacAsync);
        DpopOwnedDisposables.Add(key);
        return key;
    }


    /// <summary>
    /// Builds a DPoP-enabled <see cref="OAuthClient"/> + matching
    /// <see cref="ClientRegistration"/> for the supplied server registration,
    /// generates a fresh P-256 DPoP key, wires the client-side cache, and
    /// returns the components a test needs to drive a full DPoP-bound
    /// AuthCode round-trip.
    /// </summary>
    public DpopClientFixture CreateDpopEnabledOAuthClient(
        ClientRecord record,
        string redirectUri,
        string issuerUri)
    {
        ArgumentNullException.ThrowIfNull(record);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerUri);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> dpopKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);
        InMemoryDpopNonceCache nonceCache = new();

        InProcessTransport transport = new(Server, record, record.TenantId, issuerUri);
        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        string segment = record.TenantId.Value;
        Uri issuerUriValue = new(issuerUri);
        //RFC 9449 §4.2 — the htu claim is the URL of the inbound request. The
        //AS-side enforcement composes htu from the issuer authority + request
        //path (it has no direct access to the externally-visible URL); pin the
        //client-side endpoint URLs to the same authority so both sides agree.
        Uri baseUri = new(issuerUriValue.GetLeftPart(UriPartial.Authority));
        Uri parEndpoint = new(baseUri, ServerEndpointPaths.Par
            .Replace("{segment}", segment, StringComparison.Ordinal));
        Uri authEndpoint = new(baseUri, ServerEndpointPaths.Authorize
            .Replace("{segment}", segment, StringComparison.Ordinal));
        Uri tokenEndpoint = new(baseUri, ServerEndpointPaths.Token
            .Replace("{segment}", segment, StringComparison.Ordinal));

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUriValue,
            PushedAuthorizationRequestEndpoint = parEndpoint,
            AuthorizationEndpoint = authEndpoint,
            TokenEndpoint = tokenEndpoint
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: transport.SendAsync,
            saveStateAsync: (state, ct) =>
            {
                clientFlowStore[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, ct) =>
                ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, ct) =>
            {
                foreach(OAuthFlowState state in clientFlowStore.Values)
                {
                    if(state is Verifiable.OAuth.AuthCode.States.ParCompletedState pc
                        && string.Equals(
                            pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        return ValueTask.FromResult<OAuthFlowState?>(state);
                    }
                }

                return ValueTask.FromResult<OAuthFlowState?>(null);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseAuthorizationServerMetadataAsync: (body, ct) =>
                throw new NotImplementedException("Test host pre-resolves metadata; the parser is not exercised."),
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("DPoP gate test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, ct) =>
                ValueTask.FromResult(metadata),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: Base64UrlEncoder,
            timeProvider: Time,
            constructDpopProofAsync: (claims, key, ct) => DpopProofConstruction.BuildAsync(
                claims,
                key,
                Base64UrlEncoder,
                DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctions.SignP256Async,
                MemoryPool,
                ct),
            dpopKey: dpopKey,
            lookupDpopNonce: nonceCache.Lookup,
            storeDpopNonce: nonceCache.Store);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId(record.ClientId),
            AuthorizationServerIssuer = issuerUriValue,
            RedirectUris = [new Uri(redirectUri)],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Haip10
        };

        return new DpopClientFixture(
            new OAuthClient(infrastructure),
            registration,
            dpopKey,
            nonceCache,
            dpopKeys.PublicKey,
            dpopKeys.PrivateKey,
            clientFlowStore);
    }


    /// <summary>
    /// Returns the RFC 9449 §6 <c>cnf.jkt</c> binding recorded against the
    /// flow that issued <paramref name="accessToken"/>, or <see langword="null"/>
    /// when the token is unknown or the issuing state did not carry a binding.
    /// </summary>
    public string? GetBoundThumbprintForAccessToken(string accessToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        if(!AccessTokenIndex.TryGetValue(accessToken, out string? flowId))
        {
            return null;
        }
        if(!FlowStates.TryGetValue(flowId, out var entry))
        {
            return null;
        }
        return entry.State is ServerTokenIssuedState issued ? issued.BoundJwkThumbprint : null;
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(Disposed)
        {
            return;
        }

        Disposed = true;
        Server.Dispose();

        foreach(IDisposable owned in DpopOwnedDisposables)
        {
            owned.Dispose();
        }

        foreach(PrivateKeyMemory key in SigningKeys.Values)
        {
            key.Dispose();
        }

        foreach(PublicKeyMemory key in VerificationKeys.Values)
        {
            key.Dispose();
        }

        foreach(PrivateKeyMemory key in DecryptionKeys.Values)
        {
            key.Dispose();
        }
    }


    private static VerifierClientMetadata BuildClientMetadata(
        string clientId,
        PublicKeyMemory exchangePublicKey,
        KeyId encryptionKeyId)
    {
        string jwksJson = EphemeralEncryptionKeyPair.CreatePublicKeyJwks(
            exchangePublicKey,
            TestSetup.Base64UrlEncoder,
            SensitiveMemoryPool<byte>.Shared);

        return HaipProfile.CreateVerifierClientMetadata(clientId, jwksJson);
    }


    /// <summary>
    /// Resolves the JWK <c>kty</c> and <c>crv</c> parameters from a key's
    /// <see cref="Tag"/>. Algorithm-agile — supports EC, OKP, RSA, and
    /// post-quantum key types.
    /// </summary>
    /// <summary>
    /// Extracts the opaque token from an Auth Code <c>request_uri</c> URN.
    /// The URN form is <c>urn:ietf:params:oauth:request_uri:{token}</c> per
    /// RFC 9126 §2.2 with the <c>urn:ietf:params:oauth:request_uri</c> prefix
    /// reserved for OAuth Authorization Code flows.
    /// </summary>
    /// <remarks>
    /// OID4VP no longer needs URL parsing on the host side — the per-flow
    /// handle is carried as a first-class field on the state record
    /// (<see cref="Verifiable.OAuth.Oid4Vp.Server.States.VerifierParReceivedState.ParHandle"/>)
    /// and indexed directly. This helper is therefore Auth Code only.
    /// </remarks>
    private static string ExtractRequestUriToken(Uri requestUri)
    {
        string value = requestUri.ToString();

        const string urnPrefix = "urn:ietf:params:oauth:request_uri:";
        if(value.StartsWith(urnPrefix, StringComparison.Ordinal))
        {
            return value[urnPrefix.Length..];
        }

        return value;
    }


    /// <summary>
    /// In-process transport that routes the client's HTTP-shaped requests to the
    /// server's <see cref="AuthorizationServer.DispatchAsync"/>. Models the role
    /// of an HTTP layer plus structural router collapsed into one in-memory
    /// class. No closures — all dependencies are constructor parameters.
    /// </summary>
    [DebuggerDisplay("InProcessTransport Segment={segment}")]
    private sealed class InProcessTransport(
        AuthorizationServer server,
        ClientRecord registration,
        string segment,
        string issuerUri)
    {
        public async ValueTask<HttpResponseData> SendAsync(
            Uri endpoint,
            IReadOnlyDictionary<string, string> fields,
            OutgoingHeaders headers,
            CancellationToken cancellationToken)
        {
            //The OAuth client's transport contract is form-POST: it speaks
            //URLs and form fields. The matcher chain reads everything it
            //needs from the IncomingRequest envelope; capability narrowing
            //and method filtering happen inside the matchers themselves.
            RequestFields serverFields = new(fields);

            IncomingRequest request = new(
                Path: endpoint.AbsolutePath,
                Method: "POST",
                Fields: serverFields,
                Headers: BuildIncomingHeaders(headers),
                RouteValues: RouteValues.Empty);

            RequestContext context = new();
            context.SetTenantId(segment);
            context.SetIssuer(new Uri(issuerUri));
            context.SetRegistration(registration);

            ServerHttpResponse response = await server.DispatchAsync(
                request, context, cancellationToken).ConfigureAwait(false);

            return new HttpResponseData
            {
                Body = response.Body ?? string.Empty,
                StatusCode = response.StatusCode,
                Headers = BuildResponseHeaders(response.Headers)
            };
        }
    }


    /// <summary>
    /// Builds a <see cref="RequestHeaders"/> view over the client-side
    /// <see cref="OutgoingHeaders"/>. The in-process transport forwards every
    /// outgoing header so AS-side matchers (DPoP, RFC 9421 signing) see what
    /// production deployments see over the wire.
    /// </summary>
    private static RequestHeaders BuildIncomingHeaders(OutgoingHeaders headers)
    {
        if(headers.Values.Count == 0)
        {
            return RequestHeaders.Empty;
        }

        Dictionary<string, string[]> incoming = new(headers.Values.Count, StringComparer.OrdinalIgnoreCase);
        foreach(KeyValuePair<string, string> pair in headers.Values)
        {
            incoming[pair.Key] = [pair.Value];
        }
        return new RequestHeaders(incoming);
    }


    /// <summary>
    /// Promotes server-side <see cref="ServerHttpResponse.Headers"/> into the
    /// client-side <see cref="ResponseHeaders"/> shape. RFC 9449 §8.1 carries
    /// fresh nonces in <c>DPoP-Nonce</c> on a 400 challenge; the client's
    /// retry loop reads them via this surface.
    /// </summary>
    private static ResponseHeaders BuildResponseHeaders(ImmutableDictionary<string, string> headers)
    {
        if(headers.IsEmpty)
        {
            return ResponseHeaders.Empty;
        }

        return new ResponseHeaders { Values = headers };
    }


    /// <summary>
    /// Resolves an issuer's public key from the trust store.
    /// </summary>
    private PublicKeyMemory? ResolveIssuerKey(string issuerId)
    {
        return IssuerTrustStore.GetValueOrDefault(issuerId);
    }


    /// <summary>
    /// In-process transport that resolves the <see cref="ClientRecord"/> from
    /// the host's registration dictionary at dispatch time, rather than
    /// binding to a fixed registration at construction. Used by the dynamic-
    /// registration path where the registration does not exist at client-
    /// construction time.
    /// </summary>
    [DebuggerDisplay("LookupTransport")]
    private sealed class LookupTransport(
        AuthorizationServer server,
        ConcurrentDictionary<string, ClientRecord> registrations,
        string issuerUri)
    {
        public async ValueTask<HttpResponseData> SendAsync(
            Uri endpoint,
            IReadOnlyDictionary<string, string> fields,
            OutgoingHeaders headers,
            CancellationToken cancellationToken)
        {
            string segment = ExtractTenantSegment(endpoint.AbsolutePath);
            if(!registrations.TryGetValue(segment, out ClientRecord? registration))
            {
                return new HttpResponseData
                {
                    StatusCode = 404,
                    Body = $"No registration found for segment '{segment}'."
                };
            }

            RequestFields serverFields = new(fields);

            IncomingRequest request = new(
                Path: endpoint.AbsolutePath,
                Method: "POST",
                Fields: serverFields,
                Headers: BuildIncomingHeaders(headers),
                RouteValues: RouteValues.Empty);

            RequestContext context = new();
            context.SetTenantId(segment);
            context.SetIssuer(new Uri(issuerUri));
            context.SetRegistration(registration);

            ServerHttpResponse response = await server.DispatchAsync(
                request, context, cancellationToken).ConfigureAwait(false);

            return new HttpResponseData
            {
                Body = response.Body ?? string.Empty,
                StatusCode = response.StatusCode,
                Headers = BuildResponseHeaders(response.Headers)
            };
        }


        private static string ExtractTenantSegment(string path) =>
            ExtractTenantSegmentForTests(path);


        internal static string ExtractTenantSegmentForTests(string path)
        {
            //Test paths follow /connect/{segment}/<endpoint>. Anything else
            //returns an empty segment which will fail the registration
            //lookup and surface a 404.
            const string prefix = "/connect/";
            if(!path.StartsWith(prefix, StringComparison.Ordinal))
            {
                return string.Empty;
            }
            int start = prefix.Length;
            int end = path.IndexOf('/', start);
            return end < 0 ? path[start..] : path[start..end];
        }
    }


    /// <summary>
    /// Observer that populates the registration routing table from events.
    /// </summary>
    private sealed class RegistrationObserver(
        ConcurrentDictionary<string, ClientRecord> store,
        ConcurrentDictionary<string, string> tokenStore)
        : IObserver<ClientRegistrationEvent>
    {
        public void OnNext(ClientRegistrationEvent value)
        {
            if(value is ClientRegistered registered)
            {
                store[registered.TenantId] = registered.Registration;
                store[registered.Registration.ClientId] = registered.Registration;
                tokenStore[registered.Registration.ClientId] = registered.AccessToken.Value;
            }
            else if(value is ClientDeregistered deregistered)
            {
                store.TryRemove(deregistered.TenantId, out _);
                store.TryRemove(deregistered.ClientId, out _);
                tokenStore.TryRemove(deregistered.ClientId, out _);
            }
            else if(value is ClientUpdated updated)
            {
                store[updated.TenantId] = updated.Current;
                store[updated.Current.ClientId] = updated.Current;
            }
        }

        public void OnError(Exception error) { }

        public void OnCompleted() { }
    }
}
