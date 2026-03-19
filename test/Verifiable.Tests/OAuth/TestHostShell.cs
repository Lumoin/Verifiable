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
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;
using Verifiable.Core.Assessment;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

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
    private ConcurrentDictionary<string, ClientRegistration> Registrations { get; } = new();
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
    public IReadOnlyDictionary<string, ClientRegistration> RegistrationStore => Registrations;

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

        AuthorizationServerOptions options = new()
        {
            TimeProvider = timeProvider,
            Encoder = TestSetup.Base64UrlEncoder,
            Decoder = TestSetup.Base64UrlDecoder,
            HashFunctionSelector = DefaultHashFunctionSelector.Select,

            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult(ctx.TenantId),

            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    Registrations.TryGetValue(tenantId, out ClientRegistration? reg)
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
                        string token = ExtractRequestUriToken(vpPar.Par.RequestUri);
                        if(!string.IsNullOrWhiteSpace(token))
                        {
                            RequestUriTokenIndex[token] = flowId;
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
            },

            //The HAIP executor handles OID4VP flows (SignJar, DecryptResponse).
            //Auth Code flows do not produce actions and ignore the executor.
            //Key resolvers are read from options at call time, not captured here.
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
                    s, TestSetup.Base64UrlDecoder, SensitiveMemoryPool<byte>.Shared),
                computeSdJwtHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(
                    t, TestSetup.Base64UrlEncoder),
                hashFunctionSelector: DefaultHashFunctionSelector.Select,
                vpValidator: vpValidator,
                keyAgreementDecryptDelegate:
                    BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                keyDerivationDelegate: ConcatKdf.DefaultKeyDerivationDelegate,
                aeadDecryptDelegate: BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                pool: SensitiveMemoryPool<byte>.Shared),

            //The library signs access tokens via AccessTokenSigning by default.
            //TestHostShell supplies the two JSON serialization delegates and leaves
            //SignTokenAsync unset; tests that need non-standard signing (e.g.,
            //attestation-wrapped tokens) assign SignTokenAsync per test.
            JwtHeaderSerializer = static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            JwtPayloadSerializer = static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions),

            EndpointBuilders =
            [
                AuthCodeEndpoints.Builder,
                Oid4VpEndpoints.Builder,
                MetadataEndpoints.Builder
            ]
        };

        Server = new AuthorizationServer(options);

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

        Uri responseUri = new(baseUri, $"/connect/{segment}/direct_post");

        ClientRegistration registration = new()
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
    /// <returns>The registered <see cref="ClientRegistration"/>.</returns>
    public ClientRegistration RegisterSigningClient(
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

        ClientRegistration registration = new()
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
    /// Creates an <see cref="AuthCodeClient"/> wired to this server via in-process
    /// transport. No HTTP, no serialization — both PDAs run in the same process.
    /// </summary>
    /// <param name="registration">The client registration to wire.</param>
    /// <param name="redirectUri">The client's redirect URI.</param>
    /// <param name="issuerUri">The expected issuer URI for callback validation.</param>
    public AuthCodeClient CreateAuthCodeClient(
        ClientRegistration registration,
        string redirectUri,
        string issuerUri)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuerUri);

        InProcessTransport transport = new(
            Server, registration, registration.TenantId, issuerUri);

        Dictionary<string, OAuthFlowState> clientFlowStore = [];

        AuthCodeFlowOptions options = AuthCodeFlowOptions.Create(
            clientId: registration.ClientId,
            endpoints: new AuthorizationServerEndpoints
            {
                Issuer = issuerUri,
                PushedAuthorizationRequestEndpoint = new Uri($"{issuerUri}/par"),
                AuthorizationEndpoint = new Uri($"{issuerUri}/authorize"),
                TokenEndpoint = new Uri($"{issuerUri}/token")
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

        return new AuthCodeClient(options);
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
    /// Resolves the endpoints for a registration.
    /// </summary>
    public IReadOnlyList<ServerEndpoint> GetEndpoints(ClientRegistration registration)
        => Server.GetEndpoints(registration);


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
    /// Returns the request URI (for QR code) and the external token (for
    /// subsequent JAR and direct_post steps). The internal flow identifier
    /// never leaves this method.
    /// </summary>
    public async Task<(Uri RequestUri, string ExternalToken)> HandleParAsync(
        VerifierKeyMaterial keyMaterial,
        TransactionNonce nonce,
        PreparedDcqlQuery dcqlQuery,
        Uri baseUri,
        CancellationToken cancellationToken)
    {
        ServerEndpoint endpoint = EndpointMatcher.Find(
            GetEndpoints(keyMaterial.Registration),
            ServerCapabilityName.VerifiablePresentation, "POST", startsNewFlow: true)
            ?? throw new InvalidOperationException("PAR endpoint not found.");

        RequestContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetRequestUriBase(baseUri);
        context.SetTransactionNonce(nonce);
        context.SetPreparedQuery(dcqlQuery);
        context.SetDecryptionKeyId(keyMaterial.EncryptionKeyId);

        ServerHttpResponse response = await Server.HandleAsync(
            endpoint, new RequestFields(), context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"PAR failed with status {response.StatusCode}: {response.Body}");
        }

        string externalToken = context.GeneratedFlowId
            ?? throw new InvalidOperationException("GeneratedFlowId not set after PAR.");
        Uri requestUri = context.GeneratedRequestUri
            ?? throw new InvalidOperationException("GeneratedRequestUri not set after PAR.");

        return (requestUri, externalToken);
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

        ServerEndpoint endpoint = EndpointMatcher.Find(
            GetEndpoints(keyMaterial.Registration),
            ServerCapabilityName.VerifiablePresentation, "GET", startsNewFlow: false)
            ?? throw new InvalidOperationException("JAR request endpoint not found.");

        RequestContext context = new();
        context.SetTenantId(keyMaterial.Registration.TenantId);
        context.SetCorrelationKey(externalToken);

        ServerHttpResponse response = await Server.HandleAsync(
            endpoint, new RequestFields(), context, cancellationToken).ConfigureAwait(false);

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
        ServerEndpoint endpoint = EndpointMatcher.Find(
            GetEndpoints(keyMaterial.Registration),
            ServerCapabilityName.VerifiablePresentation, "POST", startsNewFlow: false)
            ?? throw new InvalidOperationException("Direct-post endpoint not found.");

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

        ServerHttpResponse response = await Server.HandleAsync(
            endpoint, fields, context, cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 200)
        {
            throw new InvalidOperationException(
                $"direct_post failed with status {response.StatusCode}: {response.Body}");
        }

        return (PresentationVerifiedState)GetFlowState(externalToken).State;
    }


    /// <summary>
    /// Dispatches a request by segment string. Used for edge case tests where
    /// the segment may not resolve to a valid registration (e.g., 404 tests
    /// after deregistration).
    /// </summary>
    public async ValueTask<ServerHttpResponse> DispatchBySegmentAsync(
        string segment,
        ServerCapabilityName capability,
        string httpMethod,
        RequestFields fields,
        RequestContext context,
        CancellationToken cancellationToken)
    {
        context.SetTenantId(segment);

        if(!Registrations.TryGetValue(segment, out ClientRegistration? registration))
        {
            return ServerHttpResponse.NotFound();
        }

        return await Server.DispatchAsync(
            registration, capability, httpMethod, fields, context,
            cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Deregisters a client by endpoint segment and emits a
    /// <see cref="ClientDeregistered"/> event.
    /// </summary>
    public void DeregisterClient(string segment, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(segment);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        if(!Registrations.TryGetValue(segment, out ClientRegistration? registration))
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

        if(!Registrations.TryGetValue(segment, out ClientRegistration? previous))
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

        ClientRegistration updated = previous with
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
    /// Replaces the <see cref="ClientRegistration.SigningKeys"/> map for the given
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

        if(!Registrations.TryGetValue(segment, out ClientRegistration? previous))
        {
            throw new InvalidOperationException(
                $"No registration found for segment '{segment}'.");
        }

        ClientRegistration updated = previous with
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
    /// Extracts the opaque token from a <c>request_uri</c>. Handles both the
    /// URN form (<c>urn:ietf:params:oauth:request_uri:{token}</c>) and the
    /// URL form (<c>https://host/connect/{token}/request/{token}</c>).
    /// </summary>
    private static string ExtractRequestUriToken(Uri requestUri)
    {
        string value = requestUri.ToString();

        const string urnPrefix = "urn:ietf:params:oauth:request_uri:";
        if(value.StartsWith(urnPrefix, StringComparison.Ordinal))
        {
            return value[urnPrefix.Length..];
        }

        //URL form: the last path segment is the token.
        string path = requestUri.AbsolutePath;
        int lastSlash = path.LastIndexOf('/');
        if(lastSlash >= 0 && lastSlash < path.Length - 1)
        {
            return path[(lastSlash + 1)..];
        }

        return value;
    }


    /// <summary>
    /// In-process transport that routes the client's HTTP-shaped requests to the
    /// server's <see cref="AuthorizationServer.DispatchAsync"/>. No closures — all
    /// dependencies are constructor parameters.
    /// </summary>
    [DebuggerDisplay("InProcessTransport Segment={segment}")]
    private sealed class InProcessTransport(
        AuthorizationServer server,
        ClientRegistration registration,
        string segment,
        string issuerUri)
    {
        public async ValueTask<HttpResponseData> SendAsync(
            Uri endpoint,
            IReadOnlyDictionary<string, string> fields,
            CancellationToken cancellationToken)
        {
            ServerCapabilityName capability = MapEndpointToCapability(endpoint);

            RequestFields serverFields = new(fields);

            RequestContext context = new();
            context.SetTenantId(segment);
            context.SetIssuer(new Uri(issuerUri));

            ServerHttpResponse response = await server.DispatchAsync(
                registration,
                capability,
                "POST",
                serverFields,
                context,
                cancellationToken).ConfigureAwait(false);

            return new HttpResponseData
            {
                Body = response.Body ?? string.Empty,
                StatusCode = response.StatusCode
            };
        }


        private static ServerCapabilityName MapEndpointToCapability(Uri endpoint)
        {
            string path = endpoint.AbsolutePath;

            if(path.EndsWith("/par", StringComparison.Ordinal))
            {
                return ServerCapabilityName.PushedAuthorization;
            }

            if(path.EndsWith("/token", StringComparison.Ordinal))
            {
                return ServerCapabilityName.AuthorizationCode;
            }

            if(path.EndsWith("/revoke", StringComparison.Ordinal))
            {
                return ServerCapabilityName.TokenRevocation;
            }

            throw new InvalidOperationException(
                $"Cannot map endpoint '{endpoint}' to a server capability.");
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
        ConcurrentDictionary<string, ClientRegistration> store)
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
