using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
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
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Metadata;
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
    private ConcurrentDictionary<KeyId, PrivateKeyMemory> SigningKeys { get; } = new();
    private ConcurrentDictionary<KeyId, PublicKeyMemory> VerificationKeys { get; } = new();
    private ConcurrentDictionary<KeyId, PrivateKeyMemory> DecryptionKeys { get; } = new();
    private bool Disposed { get; set; }


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
            ResolvePolicyAsync = PolicyProfiles.DefaultResolvePolicyAsync
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
            ComputeDigest = MicrosoftEntropyFunctions.ComputeDigest,

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
                    MetadataEndpoints.Builder
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
                computeDigest: MicrosoftEntropyFunctions.ComputeDigest,
                vpValidator: vpValidator,
                keyAgreementDecryptDelegate:
                    BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                keyDerivationDelegate: ConcatKdf.DefaultKeyDerivationDelegate,
                aeadDecryptDelegate: BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                pool: SensitiveMemoryPool<byte>.Shared)
        };

        Server.Validate();

        //Subscribe to populate the routing table from events.
        Server.Events.Subscribe(new RegistrationObserver(Registrations));
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
        Server.RegisterClient(registration, new RequestContext());

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

        Server.RegisterClient(registration, new RequestContext());

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

        Server.RegisterClient(registration, new RequestContext());

        return registration;
    }


    /// <summary>
    /// Creates an <see cref="OAuthClient"/> wired to this server via in-process
    /// transport. No HTTP, no serialization — both PDAs run in the same process.
    /// AuthCode flows are accessed via <see cref="OAuthClient.AuthCode"/>.
    /// </summary>
    /// <param name="registration">The client registration to wire.</param>
    /// <param name="redirectUri">The client's redirect URI.</param>
    /// <param name="issuerUri">The expected issuer URI for callback validation.</param>
    public OAuthClient CreateOAuthClient(
        ClientRecord registration,
        string redirectUri,
        string issuerUri)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerUri);

        InProcessTransport transport = new(
            Server, registration, registration.TenantId, issuerUri);

        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        string segment = registration.TenantId.Value;
        Uri baseUri = new($"https://verifier.example.com");
        OAuthClientOptions options = OAuthClientOptions.Create(
            clientId: registration.ClientId,
            endpoints: new AuthorizationServerEndpoints
            {
                Issuer = issuerUri,
                PushedAuthorizationRequestEndpoint = new Uri(baseUri, ServerEndpointPaths.Par
                    .Replace("{segment}", segment, StringComparison.Ordinal)),
                AuthorizationEndpoint = new Uri(baseUri, ServerEndpointPaths.Authorize
                    .Replace("{segment}", segment, StringComparison.Ordinal)),
                TokenEndpoint = new Uri(baseUri, ServerEndpointPaths.Token
                    .Replace("{segment}", segment, StringComparison.Ordinal))
            },
            redirectUri: new Uri(redirectUri),
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
            sendFormPostAsync: transport.SendAsync,
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            callbackValidator: new ClaimIssuer<ValidationContext>(
                "callback-haip10", ValidationProfiles.CallbackHaip10Rules(), Time),
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            timeProvider: Time);

        return new OAuthClient(options);
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


    /// <inheritdoc/>
    public void Dispose()
    {
        if(Disposed)
        {
            return;
        }

        Disposed = true;
        Server.Dispose();

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
                Headers: RequestHeaders.Empty,
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
                StatusCode = response.StatusCode
            };
        }
    }


    /// <summary>
    /// Resolves an issuer's public key from the trust store.
    /// </summary>
    private PublicKeyMemory? ResolveIssuerKey(string issuerId)
    {
        return IssuerTrustStore.GetValueOrDefault(issuerId);
    }


    /// <summary>
    /// Observer that populates the registration routing table from events.
    /// </summary>
    private sealed class RegistrationObserver(
        ConcurrentDictionary<string, ClientRecord> store)
        : IObserver<ClientRegistrationEvent>
    {
        public void OnNext(ClientRegistrationEvent value)
        {
            if(value is ClientRegistered registered)
            {
                store[registered.TenantId] = registered.Registration;
                store[registered.Registration.ClientId] = registered.Registration;
            }
            else if(value is ClientDeregistered deregistered)
            {
                store.TryRemove(deregistered.TenantId, out _);
                store.TryRemove(deregistered.ClientId, out _);
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
