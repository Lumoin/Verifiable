using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Text.Json;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.Model.SelectiveDisclosure.Strategy;
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
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Audit;
using Verifiable.OAuth.Server.Keys;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Server.Registration;
using Verifiable.OAuth.Server.States;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Per-host state for a single test-fixture <see cref="AuthorizationServer"/>
/// deployment: registrations, key stores, flow-handle indexes, and the
/// associated Kestrel + HttpClient when the host is serving HTTP.
/// </summary>
/// <remarks>
/// <para>
/// One <see cref="TestHostShell"/> may own multiple <see cref="HostedAuthorizationServer"/>
/// instances — typically one per deployment role in a multi-party flow
/// (Verifier, Federation Anchor, Resource Server, OAuth client, etc.).
/// Each hosted server is wired independently, has its own state, and binds
/// its own Kestrel port; the shell is the orchestrator, not a participant.
/// </para>
/// <para>
/// Production parallel: this object stands in for the constellation of
/// dependency-injected services and configuration that a real
/// <c>WebApplication</c> would wire together for a single
/// <see cref="AuthorizationServer"/> instance.
/// </para>
/// </remarks>
[DebuggerDisplay("HostedAuthorizationServer Name={Name} Clients={Registrations.Count} HasHttp={KestrelServer != null}")]
internal sealed class HostedAuthorizationServer
{
    /// <summary>The host's role name (e.g. "verifier", "anchor", "resource-server").</summary>
    public string Name { get; }

    /// <summary>The wired authorization server. All HTTP and in-process dispatch routes through this.</summary>
    /// <remarks>
    /// Two-phase init: the host is constructed empty so the
    /// <see cref="AuthorizationServerIntegration"/> delegates can close over
    /// <see cref="Registrations"/> / <see cref="FlowStates"/> / etc. before the
    /// <see cref="AuthorizationServer"/> itself is built; <see cref="Build"/>
    /// assigns the wired server here.
    /// </remarks>
    public AuthorizationServer Server { get; internal set; } = null!;


    //Per-host stores. Every AuthorizationServer integration delegate that
    //carries cross-request state closes over these dictionaries — registration
    //routing, flow persistence, secondary indexes for token/handle lookups,
    //and the key material backing the cryptography resolvers.

    public ConcurrentDictionary<string, ClientRecord> Registrations { get; } = new();
    public ConcurrentDictionary<string, (OAuthFlowState State, int StepCount)> FlowStates { get; } = new();
    public ConcurrentDictionary<string, string> RequestUriTokenIndex { get; } = new();
    public ConcurrentDictionary<string, string> CodeIndex { get; } = new();
    public ConcurrentDictionary<string, string> JtiIndex { get; } = new();
    public ConcurrentDictionary<string, string> AccessTokenIndex { get; } = new();
    public ConcurrentDictionary<string, string> RefreshTokenIndex { get; } = new();
    public ConcurrentDictionary<KeyId, PrivateKeyMemory> SigningKeys { get; } = new();
    public ConcurrentDictionary<KeyId, PublicKeyMemory> VerificationKeys { get; } = new();
    public ConcurrentDictionary<KeyId, PrivateKeyMemory> DecryptionKeys { get; } = new();
    public ConcurrentDictionary<string, string> RegistrationAccessTokens { get; } = new();


    //Kestrel state — populated when StartHttpHostAsync runs against this host.

    public global::Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServer? KestrelServer { get; set; }
    public Uri? HttpBaseAddress { get; set; }
    public System.Net.Http.HttpClient? SharedHttpClient { get; set; }


    internal HostedAuthorizationServer(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        Name = name;
    }


    /// <summary>
    /// Constructs a fully wired <see cref="HostedAuthorizationServer"/> whose
    /// <see cref="Server"/> integration delegates close over the new host's
    /// own dictionaries. Every host built by this method is independent —
    /// flow states, registrations, and key material live exclusively on the
    /// returned instance.
    /// </summary>
    /// <param name="name">Host role name; used for diagnostics.</param>
    /// <param name="timeProvider">Time provider for all timestamps.</param>
    /// <param name="subjectClaims">
    /// Shared (shell-level) subject claim store. The
    /// <see cref="AuthorizationServerIntegration.ResolveOidcClaimsAsync"/>
    /// delegate reads from this dictionary so claim seeding stays at the
    /// orchestrator level rather than being host-private.
    /// </param>
    /// <param name="resolveIssuerKey">
    /// Trust-anchor lookup for credential issuer verification. Shared by all
    /// hosts built from the same shell so issuer trust is a single source of
    /// truth.
    /// </param>
    /// <param name="vpValidator">VP token validator (HAIP 1.0 SD-JWT rules by default).</param>
    public static HostedAuthorizationServer Build(
        string name,
        TimeProvider timeProvider,
        Dictionary<string, OidcClaims> subjectClaims,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ClaimIssuer<ValidationContext> vpValidator,
        MdocVpVerificationSeams? mdocSeams = null,
        SdCwtVpVerificationSeams? sdCwtSeams = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        TimingPolicy? timings = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(subjectClaims);
        ArgumentNullException.ThrowIfNull(resolveIssuerKey);
        ArgumentNullException.ThrowIfNull(vpValidator);

        HostedAuthorizationServer host = new(name);

        AuthorizationServerIntegration integration = new()
        {
            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult(ctx.TenantId),

            ResolveOidcClaimsAsync = (subject, scope, tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    subjectClaims.TryGetValue(subject, out OidcClaims? claims)
                        ? claims : null),

            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    host.Registrations.TryGetValue(tenantId, out ClientRecord? reg)
                        ? reg : null),

            DeleteFlowStateAsync = (tenantId, flowId, ctx, ct) =>
            {
                //Refresh-token rotation invokes this to invalidate the
                //presented refresh state. Also remove from the secondary
                //refresh-token index so the next presentation of the rotated-
                //out token cleanly fails the correlation lookup.
                if(host.FlowStates.TryRemove(flowId, out var removed)
                    && removed.State is ServerRefreshTokenIssuedState removedRefresh)
                {
                    host.RefreshTokenIndex.TryRemove(removedRefresh.RefreshToken, out _);
                }

                return ValueTask.CompletedTask;
            },

            SaveFlowStateAsync = (tenantId, flowId, state, stepCount, ctx, ct) =>
            {
                host.FlowStates[flowId] = (state, stepCount);

                //Build secondary indexes from the state so that continuing
                //endpoints can resolve external handles back to the flowId.
                //This mirrors SQL indexed columns on the same row.
                //Single-tenant fixture: tenantId is accepted to match the delegate
                //signature but not used in the keying. Multi-tenant tests would key
                //by (tenantId, flowId) compounds.
                switch(state)
                {
                    case ParRequestReceivedState par:
                    {
                        string token = TestHostShell.ExtractRequestUriToken(par.RequestUri);
                        if(!string.IsNullOrWhiteSpace(token))
                        {
                            host.RequestUriTokenIndex[token] = flowId;
                        }

                        break;
                    }
                    case ServerCodeIssuedState codeIssued:
                    {
                        host.CodeIndex[codeIssued.CodeHash] = flowId;
                        break;
                    }
                    case VerifierParReceivedState vpPar:
                    {
                        //The OID4VP PAR endpoint stamps the per-flow handle directly on
                        //the state. No URL parsing — the handle is first-class.
                        if(!string.IsNullOrWhiteSpace(vpPar.ParHandle))
                        {
                            host.RequestUriTokenIndex[vpPar.ParHandle] = flowId;
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
                        host.JtiIndex[$"{jti.Issuer}:{jti.Jti}"] = flowId;
                        break;
                    }
                    case ServerTokenIssuedState:
                    {
                        //Capture access_token → flowId so test code can recover the
                        //Confirmation binding for a known access token. The
                        //IssuedTokenSet carries the live JWS strings on the request
                        //context (they are never persisted onto state).
                        string? accessToken = ctx.IssuedTokens?.AccessToken;
                        if(!string.IsNullOrEmpty(accessToken))
                        {
                            host.AccessTokenIndex[accessToken] = flowId;
                        }

                        break;
                    }
                    case ServerRefreshTokenIssuedState refresh:
                    {
                        //Refresh tokens index by their wire string. Rotation
                        //replaces the entry on every refresh-grant call.
                        host.RefreshTokenIndex[refresh.RefreshToken] = flowId;
                        break;
                    }
                }

                return ValueTask.CompletedTask;
            },

            LoadFlowStateAsync = (tenantId, flowId, ctx, ct) =>
                ValueTask.FromResult(
                    host.FlowStates.TryGetValue(flowId, out var entry)
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
                        host.JtiIndex.TryGetValue(externalHandle, out string? jtiFlowId)
                            ? jtiFlowId : null);
                }

                //Refresh-token grant — the endpoint Kind is FlowKind.RefreshToken
                //and the external handle is the opaque refresh-token string.
                if(flowKind == FlowKind.RefreshToken)
                {
                    return ValueTask.FromResult<string?>(
                        host.RefreshTokenIndex.TryGetValue(externalHandle, out string? refreshFlowId)
                            ? refreshFlowId : null);
                }

                //Try each secondary index. The application knows which handle
                //types exist — this mirrors a SQL query with OR conditions.
                if(host.RequestUriTokenIndex.TryGetValue(externalHandle, out string? flowId))
                {
                    return ValueTask.FromResult<string?>(flowId);
                }

                if(host.CodeIndex.TryGetValue(externalHandle, out flowId))
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

                //RFC 9728 §3: the protected-resource metadata path is formed by
                //INSERTION between host and the identifier's path, not by the
                //fixture's /connect/{segment}/<suffix> scheme — delegate to
                //ComposeEndpointPath, which owns that special case.
                if(string.Equals(endpointKey, WellKnownEndpointNames.ProtectedResourceMetadata, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}{TestHostShell.ComposeEndpointPath(endpointKey, segment)}"));
                }

                //Phase 9h chunk 9 — the library asks for endpoint URLs solely
                //The path-suffix dispatch lives in a private static helper
                //(EndpointPathSuffix) shared with ComposeEndpointPath /
                //ComposeEndpointUri — fixture code that needs concrete URIs
                //synchronously calls the same source-of-truth.
                string? suffix = TestHostShell.EndpointPathSuffix(endpointKey);
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
            //includes ExchangeContext for applications that classify on
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

            //Phase 9h chunk 4/8 — per-call decision points. Wired to the
            //library defaults: full registration capability set (no
            //attenuation), no-op inspection, public-subject identity.
            //Applications that need CAEP/RISC attenuation, audit emission,
            //or pairwise subjects supply their own delegate.
            ResolveCapabilitiesAsync = DefaultCapabilityResolver.ResolveAsync,
            InspectAsync = DefaultInspector.NoOpAsync,
            ResolveSubjectIdentifierAsync = DefaultSubjectIdentifierResolver.PublicAsync,
            GenerateIdentifierAsync = DefaultIdentifierGenerator.ForTimeProvider(timeProvider),

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
                    host.RegistrationAccessTokens.TryGetValue(clientId, out string? stored)
                    && string.Equals(stored, presented, StringComparison.Ordinal))
        };

        AuthorizationServerCryptography cryptography = new()
        {
            SigningKeyResolver = (keyId, tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    host.SigningKeys.TryGetValue(keyId, out PrivateKeyMemory? key)
                        ? key : null),

            VerificationKeyResolver = (keyId, tenantId, ctx, ct) =>
                ValueTask.FromResult(
                    host.VerificationKeys.TryGetValue(keyId, out PublicKeyMemory? key)
                        ? key : null),

            DecryptionKeyResolver = (keyId, ctx, ct) =>
                ValueTask.FromResult(
                    host.DecryptionKeys.TryGetValue(keyId, out PrivateKeyMemory? key)
                        ? key : null),

            BuildJwksDocumentAsync = (registration, ctx, ct) =>
            {
                List<JsonWebKey> jwks = [];

                //OAuth /jwks publishes OAuth/OIDC token-signing keys and JAR
                //signing keys. Federation entity-signing keys live behind
                //the federation EC's own jwks claim (served at
                ///.well-known/openid-federation), so skip them here. A real
                //deployment with separate JWKS endpoints would scope
                //similarly per usage-context.
                foreach(KeyValuePair<KeyUsageContext, SigningKeySet> entry in registration.SigningKeys)
                {
                    if(entry.Key == KeyUsageContext.FederationEntitySignature)
                    {
                        continue;
                    }

                    foreach(KeyId publishedKeyId in entry.Value.PublishedKeys)
                    {
                        if(!host.VerificationKeys.TryGetValue(publishedKeyId, out PublicKeyMemory? publicKey))
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
                ?? throw new FormatException("Payload JSON parsed to null."),

            //OID4VP §5.9.3 redirect_uri prefix path serialises the JAR
            //inline; the dcql_query and client_metadata claims need their
            //own wire-form serialisers since that path bypasses the
            //executor's delegate-injected ones.
            DcqlQuerySerializer = static query =>
                JsonSerializer.Serialize(query, TestSetup.DefaultSerializationOptions),
            ClientMetadataSerializer = static metadata =>
                JsonSerializer.Serialize(metadata, TestSetup.DefaultSerializationOptions)
        };

        host.Server = new AuthorizationServer
        {
            Integration = integration,
            Cryptography = cryptography,
            Codecs = codecs,
            TimeProvider = timeProvider,
            Timings = timings ?? TimingPolicy.Default,

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
                    RegistrationEndpoints.Builder,
                    UserInfoEndpoints.Builder,
                    Verifiable.OAuth.Federation.FederationEndpoints.Builder,
                    Verifiable.OAuth.AuthZen.AuthZenEndpoints.Builder,
                    Verifiable.OAuth.Ssf.SsfTransmitterEndpoints.Builder,
                    Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataEndpoints.Builder
                ]),
                TokenProducers = new TokenProducerSet(
                [
                    TokenProducer.Rfc9068AccessToken,
                    TokenProducer.Oidc10IdToken
                ]),
                ClaimIssuer = ContributionProfiles.StandardClaimIssuer(timeProvider)
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
                vpValidators: BuildVpValidators(vpValidator, mdocSeams, sdCwtSeams, timeProvider),
                keyAgreementDecryptDelegate:
                    BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
                keyDerivationDelegate: ConcatKdf.DefaultKeyDerivationDelegate,
                aeadDecryptDelegate: BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
                pool: SensitiveMemoryPool<byte>.Shared,
                keyAgreementEncryptDelegate:
                    BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                aeadEncryptDelegate: BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                tagToEpkCrvConverter: CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                mdocSeams: mdocSeams,
                sdCwtSeams: sdCwtSeams,
                saltReuseSeam: saltReuseSeam,
                //Wire the Core disclosure engine behind the verifier's assessment seam:
                //run DcqlDisclosure over the disclosed claims and read graph.Satisfied
                //(DCQL satisfaction) and disclosed-minus-selected (over-disclosure).
                assessDisclosure: static async (assessContext, cancellationToken) =>
                {
                    DcqlDisclosureResult<IReadOnlyDictionary<CredentialPath, object?>> result =
                        await DcqlDisclosure.ComputeStrategyAsync(
                            assessContext.CredentialQuery,
                            assessContext.DisclosedClaims,
                            //Supply the verified issuer so DcqlEvaluator can enforce a
                            //trusted_authorities constraint fail-closed; without it the
                            //evaluator skips the check (it has no authority to compare).
                            DisclosedClaimsDcqlAdapter.CreateMetadataExtractor(
                                assessContext.CredentialQuery.Format!, issuer: assessContext.Issuer),
                            DisclosedClaimsDcqlAdapter.ClaimExtractor,
                            cancellationToken: cancellationToken).ConfigureAwait(false);

                    //Satisfaction is result.Satisfied — the DCQL match verdict (format / type /
                    //trusted_authorities / claim values) ANDed with lattice disclosure adequacy.
                    //Over-disclosure is any disclosed path the engine did not select as appropriate.
                    DisclosureStrategyGraph<IReadOnlyDictionary<CredentialPath, object?>> graph = result.Graph;
                    bool satisfied = result.Satisfied;
                    bool overDisclosed;
                    if(graph.Decisions.Count > 0)
                    {
                        IReadOnlySet<CredentialPath> selected = graph.Decisions[0].SelectedPaths;
                        overDisclosed = false;
                        foreach(CredentialPath disclosedPath in assessContext.DisclosedClaims.Keys)
                        {
                            if(!selected.Contains(disclosedPath))
                            {
                                overDisclosed = true;
                                break;
                            }
                        }
                    }
                    else
                    {
                        //No decision -> the query's required claims were not met.
                        overDisclosed = assessContext.DisclosedClaims.Count > 0;
                    }

                    return new Oid4VpDisclosureAssessment
                    {
                        Satisfied = satisfied,
                        OverDisclosed = overDisclosed
                    };
                })
        };

        host.Server.Validate();

        //Subscribe to populate the routing table from events.
        host.Server.Events.Subscribe(new RegistrationObserver(host.Registrations, host.RegistrationAccessTokens));

        return host;
    }


    /// <summary>
    /// Builds the format-keyed VP-token validator map the OID4VP executor
    /// dispatches through. SD-JWT is always present; the mso_mdoc validator
    /// (HAIP 1.0 mdoc rules) is added only when the host was built with mdoc
    /// verification seams, mirroring a deployment that opts into mdoc support.
    /// </summary>
    private static Dictionary<string, ClaimIssuer<ValidationContext>> BuildVpValidators(
        ClaimIssuer<ValidationContext> sdJwtValidator,
        MdocVpVerificationSeams? mdocSeams,
        SdCwtVpVerificationSeams? sdCwtSeams,
        TimeProvider timeProvider)
    {
        var validators = new Dictionary<string, ClaimIssuer<ValidationContext>>(StringComparer.Ordinal)
        {
            [DcqlCredentialFormats.SdJwt] = sdJwtValidator
        };

        if(mdocSeams is not null)
        {
            validators[DcqlCredentialFormats.MsoMdoc] = new ClaimIssuer<ValidationContext>(
                "vp-haip10-mdoc-verifier",
                ValidationProfiles.Haip10MdocRules(),
                timeProvider);
        }

        if(sdCwtSeams is not null)
        {
            validators[DcqlCredentialFormats.SdCwt] = new ClaimIssuer<ValidationContext>(
                "vp-haip10-sd-cwt-verifier",
                ValidationProfiles.Haip10SdCwtRules(),
                timeProvider);
        }

        return validators;
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
