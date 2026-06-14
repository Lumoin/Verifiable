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
using Verifiable.Server.Pipeline;
using Verifiable.OAuth.Server.Registration;
using Verifiable.OAuth.Server.States;
using Verifiable.OAuth.Siop.Server;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Validation;
using Verifiable.Vcalm;
using Verifiable.Vcalm.Exchange;
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
    /// <see cref="EndpointServer"/> itself is built; <see cref="Build"/>
    /// assigns the wired server here.
    /// </remarks>
    public EndpointServer Server { get; internal set; } = null!;


    //Per-host stores. Every AuthorizationServer integration delegate that
    //carries cross-request state closes over these dictionaries — registration
    //routing, flow persistence, secondary indexes for token/handle lookups,
    //and the key material backing the cryptography resolvers.

    public ConcurrentDictionary<string, ClientRecord> Registrations { get; } = new();
    public ConcurrentDictionary<string, (FlowState State, int StepCount)> FlowStates { get; } = new();
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
    /// <param name="resolveDidVerificationKey">
    /// SIOPv2 §11.1 DID resolution seam for Self-Issued ID Tokens of the Decentralized
    /// Identifier Subject Syntax Type. Shared from the shell so the DID trust map is a single
    /// source of truth, mirroring <paramref name="resolveIssuerKey"/>. When
    /// <see langword="null"/> the SIOP validator fails closed on a DID subject.
    /// </param>
    public static HostedAuthorizationServer Build(
        string name,
        TimeProvider timeProvider,
        Dictionary<string, OidcClaims> subjectClaims,
        ResolveIssuerKeyDelegate resolveIssuerKey,
        ClaimIssuer<ValidationContext> vpValidator,
        MdocVpVerificationSeams? mdocSeams = null,
        SdCwtVpVerificationSeams? sdCwtSeams = null,
        CommitmentReuseDetectionSeam? saltReuseSeam = null,
        TimingPolicy? timings = null,
        Verifiable.OAuth.Siop.ResolveDidVerificationKeyDelegate? resolveDidVerificationKey = null)
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
                ValueTask.FromResult<IRegistrationRecord?>(
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
                    case SiopRequestPreparedState siopPrepared:
                    {
                        //The SIOP preparation endpoint stamps the per-flow request handle
                        //directly on the state. Index it so the response endpoint's state echo
                        //resolves back to the flowId through ResolveCorrelationKeyAsync — the
                        //same RequestUriTokenIndex path the OID4VP handle uses.
                        if(!string.IsNullOrWhiteSpace(siopPrepared.RequestHandle))
                        {
                            host.RequestUriTokenIndex[siopPrepared.RequestHandle] = flowId;
                        }

                        break;
                    }
                    case SiopRequestObjectServedState siopServed:
                    {
                        //The by-reference §9 path advances past SiopRequestPreparedState to the
                        //served state. Keep the per-flow handle indexed so both the request_uri GET
                        //(CorrelationKey) and the subsequent id_token POST (state echo) resolve back
                        //to the flowId — the parallel of VerifierJarServedState carrying ParHandle.
                        if(!string.IsNullOrWhiteSpace(siopServed.RequestHandle))
                        {
                            host.RequestUriTokenIndex[siopServed.RequestHandle] = flowId;
                        }

                        break;
                    }
                    case VcalmExchangePendingState exchangePending:
                    {
                        //VCALM §3.6: index the exchange id -> flowId so the §3.6.5 participate POST's
                        //{localExchangeId} resolves back to the flow id (ResolveCorrelationKeyAsync) and
                        //the stateless §3.6.4 / §3.6.6 reads resolve it (ResolveVcalmExchangeFlowIdAsync).
                        //The same RequestUriTokenIndex path the OID4VP / SIOP handles use.
                        if(!string.IsNullOrWhiteSpace(exchangePending.ExchangeId))
                        {
                            host.RequestUriTokenIndex[exchangePending.ExchangeId] = flowId;
                        }

                        break;
                    }
                    case VcalmExchangeActiveState exchangeActive:
                    {
                        //Keep the index live across the §3.6.5 advance so a subsequent participate POST
                        //and a §3.6.6 read still resolve to the flow id.
                        if(!string.IsNullOrWhiteSpace(exchangeActive.ExchangeId))
                        {
                            host.RequestUriTokenIndex[exchangeActive.ExchangeId] = flowId;
                        }

                        break;
                    }
                    case VcalmExchangeCompleteState exchangeComplete:
                    {
                        if(!string.IsNullOrWhiteSpace(exchangeComplete.ExchangeId))
                        {
                            host.RequestUriTokenIndex[exchangeComplete.ExchangeId] = flowId;
                        }

                        break;
                    }
                    case VcalmExchangeInvalidState { ExchangeId.Length: > 0 } exchangeInvalid:
                    {
                        host.RequestUriTokenIndex[exchangeInvalid.ExchangeId] = flowId;
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
                        : ((FlowState?)null, 0)),

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
                Uri? baseUri = ((ClientRecord)registration).IssuerUri ?? ctx.Issuer;
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

                //Per-flow SIOPv2 §9 request_uri — the same per-flow shape as the OID4VP request_uri,
                //incorporating the SIOP request handle the preparation endpoint placed on the
                //context. This fixture uses /connect/{segment}/siop_request_object/{handle}.
                if(string.Equals(endpointKey, SiopVerifierEndpointKeys.RequestUri, StringComparison.Ordinal))
                {
                    string? handle = ctx.SiopRequestHandle;
                    if(string.IsNullOrWhiteSpace(handle))
                    {
                        return ValueTask.FromResult<Uri?>(null);
                    }

                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}/connect/{segment}/siop_request_object/{handle}"));
                }

                //VCALM §3.6 vcapi participation URL — the per-exchange URL the §3.6.4 protocols response
                //and the §3.6.3 create Location header carry. The exchange engine stamped the exchange
                //id on the context before asking, so the fixture appends it to the /exchanges collection
                //path: /connect/{segment}/vcalm/exchanges/{exchangeId}.
                if(string.Equals(endpointKey, WellKnownVcalmEndpointNames.VcalmParticipateInExchange, StringComparison.Ordinal)
                    && ctx.VcalmExchangeId is { } vcalmExchangeId)
                {
                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}/connect/{segment}/vcalm/exchanges/{vcalmExchangeId}"));
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

                //OID4VCI §12.2.2 Credential Issuer Metadata — same INSERTION shape as the
                //RFC 9728 protected-resource metadata above; ComposeEndpointPath owns the case.
                if(string.Equals(endpointKey, WellKnownEndpointNames.Oid4VciCredentialIssuerMetadata, StringComparison.Ordinal))
                {
                    return ValueTask.FromResult<Uri?>(
                        new Uri($"{authority}{TestHostShell.ComposeEndpointPath(endpointKey, segment)}"));
                }

                //RFC 8414 §3 Authorization Server Metadata — the §3 default well-known
                //location formed by the same INSERTION shape between host and the issuer's
                //path component; ComposeEndpointPath owns the case.
                if(string.Equals(endpointKey, WellKnownEndpointNames.MetadataOAuthAuthorizationServer, StringComparison.Ordinal))
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
                    BaseMemoryPool.Shared,
                    ct),

            //Per-request policy resolution. The default dispatches on
            //ClientRecord.Profile across the three shipped profiles;
            //an unset Profile falls back to PolicyProfile.Fapi20
            //(FAPI 2.0 / HAIP-aligned).
            ResolvePolicyAsync = (registration, ctx, ct) =>
                PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, ctx, ct),

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

                //RFC 9396 §10/§14.5 authorization_details_types — an absent member leaves this
                //null (the client registered no restriction); a present array becomes the allowlist.
                List<string>? authorizationDetailsTypes = null;
                if(root.TryGetProperty(
                    AuthorizationDetailsParameterNames.AuthorizationDetailsTypes, out JsonElement adt))
                {
                    authorizationDetailsTypes = [];
                    foreach(JsonElement el in adt.EnumerateArray())
                    {
                        if(el.GetString() is string typeValue)
                        {
                            authorizationDetailsTypes.Add(typeValue);
                        }
                    }
                }

                return ValueTask.FromResult(new ClientMetadata
                {
                    RedirectUris = redirectUris,
                    ClientName = clientName,
                    Scope = scope,
                    TokenEndpointAuthMethod = authMethod,
                    AuthorizationDetailsTypes = authorizationDetailsTypes
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

        //The shared action executor holds the handlers of every stateful flow this host runs.
        //The HAIP executor seeds it with the OID4VP verifier handlers (SignJar, DecryptResponse);
        //SiopVerifierExecutor.Register then contributes the SIOPv2 ValidateSelfIssuedIdToken handler
        //onto the SAME instance, so a single registry serves both flows.
        OAuthActionExecutor executor = HaipOid4VpVerifierExecutor.Create(
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
                s, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag),
            computeSdJwtHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(
                t, TestSetup.Base64UrlEncoder),
            computeDigest: MicrosoftEntropyFunctions.ComputeDigestAsync,
            vpValidators: BuildVpValidators(vpValidator, mdocSeams, sdCwtSeams, timeProvider),
            keyAgreementDecryptDelegate:
                BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            keyDerivationDelegate: ConcatKdf.DefaultKeyDerivationDelegate,
            aeadDecryptDelegate: BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            pool: BaseMemoryPool.Shared,
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
            });

        //SIOPv2 RP flow's §11.1 ValidateSelfIssuedIdToken handler AND the §12 combined-response
        //ValidateCombinedSiopResponse handler, contributed onto the shared executor alongside the
        //OID4VP handlers above. The §12 handler reuses the SAME vp_token-verification seams the
        //OID4VP executor was wired with — the shared issuer-key lookup, the SD-JWT parser, the
        //hash-input function, and the digest function — so combined responses validate their
        //vp_token through the identical SdJwtVpTokenVerification pipeline.
        SiopVerifierExecutor.Register(
            executor,
            TestSetup.Base64UrlDecoder,
            TestSetup.Base64UrlEncoder,
            headerSerializer: header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)header,
                TestSetup.DefaultSerializationOptions),
            payloadSerializer: payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                (Dictionary<string, object>)payload,
                TestSetup.DefaultSerializationOptions),
            pool: BaseMemoryPool.Shared,
            timeProvider: timeProvider,
            resolveDidVerificationKey: resolveDidVerificationKey,
            resolveIssuerKey: resolveIssuerKey,
            parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                s, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, TestSalts.TestSaltTag),
            computeSdJwtHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(
                t, TestSetup.Base64UrlEncoder),
            computeDigest: MicrosoftEntropyFunctions.ComputeDigestAsync,
            saltReuseSeam: saltReuseSeam);

        //The OAuth family configuration the endpoints read — cryptography, codecs,
        //timings, token producers, the claim issuer, and the OAuth action executor —
        //lives on the family integration, reached through server.OAuth().
        integration.Cryptography = cryptography;
        integration.Codecs = codecs;
        integration.Timings = timings ?? TimingPolicy.Default;
        integration.TokenProducers = new TokenProducerSet(
        [
            TokenProducer.Rfc9068AccessToken,
            TokenProducer.Oidc10IdToken
        ]);
        integration.ClaimIssuer = ContributionProfiles.StandardClaimIssuer(timeProvider);

        //The shared executor (built above) holds the OID4VP verifier handlers
        //(SignJar, DecryptResponse) AND the SIOPv2 ValidateSelfIssuedIdToken handler.
        //Auth Code flows do not produce actions and ignore the executor.
        integration.ActionExecutor = executor;

        host.Server = new EndpointServer
        {
            Integration = integration,
            TimeProvider = timeProvider,

            //The fold pipeline is configured up-front via the neutral ServerConfiguration
            //(endpoint builders only). TestHostShell wires the library-shipped endpoint
            //builders; tests that need a different builder set apply a new configuration
            //via Server.ApplyConfiguration before dispatching.
            Configuration = new Verifiable.Server.ServerConfiguration
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
                    Verifiable.OAuth.ProtectedResource.ProtectedResourceMetadataEndpoints.Builder,
                    Verifiable.OAuth.Logout.GlobalTokenRevocationEndpoints.Builder,
                    Verifiable.OAuth.Logout.EndSessionEndpoints.Builder,
                    Verifiable.OAuth.Oid4Vci.Oid4VciEndpoints.Builder,
                    SiopVerifierEndpoints.Builder,
                    Verifiable.Vcalm.VcalmVerifierEndpoints.Builder,
                    Verifiable.Vcalm.VcalmIssuerEndpoints.Builder,
                    Verifiable.Vcalm.VcalmStatusEndpoints.Builder,
                    Verifiable.Vcalm.VcalmHolderEndpoints.Builder,
                    Verifiable.Vcalm.Exchange.VcalmExchangeEndpoints.Builder,
                    Verifiable.Vcalm.VcalmWorkflowEndpoints.Builder,
                    Verifiable.Vcalm.VcalmInteractionEndpoints.Builder
                ])
            },

            //The neutral host drives the PDA's effectful loop through this delegate.
            //It bridges the host-generic PdaAction to the OAuth executor, which owns
            //the OID4VP / SIOP action handlers. Auth Code flows produce no actions.
            ActionExecutor = (action, ctx, ct) =>
                executor.ExecuteAsync((OAuthAction)action, ctx, ct)
        };

        //Register the OAuth family integration so endpoints reach it via server.OAuth().
        host.Server.AddIntegration(integration);

        //Register the W3C VCALM family integration so the VCALM issuer / verifier endpoints reach
        //their seams via server.Vcalm(). Tests configure the VCALM seams (parsers, Data Integrity
        //verification / issuance, challenge and credential stores, request-size cap) on this
        //instance through app.Server.Vcalm() after construction.
        host.Server.AddIntegration(new Verifiable.Vcalm.VcalmIntegration());

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
