using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Keys;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Test-side resource server host. Parallel of
/// <see cref="Verifiable.Tests.OAuth.TestHostShell"/>; hosts a
/// <c>/protected</c> endpoint and the RFC 9728 §3
/// <c>/.well-known/oauth-protected-resource</c> location via a slim-builder
/// HTTPS listener + <see cref="ResourceServerHttpApplication"/>. Tests bring
/// up this host alongside <see cref="Verifiable.Tests.OAuth.TestHostShell"/>
/// (AS) to exercise the full AS → token → RS flow over real HTTP.
/// </summary>
/// <remarks>
/// <para>
/// The RFC 9728 document is never hand-formatted: the shell composes a
/// minimal <see cref="EndpointServer"/> whose only endpoint builder is
/// <see cref="ProtectedResourceMetadataEndpoints.Builder"/>, so the served
/// bytes traverse the identical library path — capability gate, §3 path
/// matcher, §3.2 emission — a co-located production deployment uses.
/// </para>
/// <para>
/// OPRM coherence (the interop event's MCP-Server invariant): a resource
/// server must accept tokens only from an authorization server its own
/// metadata document names. The constructor therefore asserts
/// <see cref="ResourceServerIntegration.TrustedIssuer"/> is one of the
/// advertised <c>authorization_servers</c> values, so the document and the
/// validator can never disagree about who mints acceptable tokens.
/// </para>
/// </remarks>
[DebuggerDisplay("TestResourceServerShell BaseAddress={HttpBaseAddress}")]
internal sealed class TestResourceServerShell: IAsyncDisposable
{
    private global::Microsoft.AspNetCore.Builder.WebApplication? webApplication;
    private EndpointServer? metadataServer;
    private bool Disposed { get; set; }

    public ResourceServerIntegration Integration { get; }
    public VerificationDelegate VerifySignature { get; }


    /// <summary>
    /// The scope a token must carry to reach <c>/protected</c>, or
    /// <see langword="null"/> when the host performs no scope enforcement.
    /// A valid token without it is refused <c>403</c>
    /// <c>insufficient_scope</c> per RFC 6750 §3.1, with the challenge's
    /// <c>scope</c> attribute naming this value.
    /// </summary>
    public string? RequiredScope { get; }


    /// <summary>
    /// The <c>authorization_servers</c> issuer identifiers the RFC 9728
    /// document advertises. Defaults to exactly the trusted issuer; a caller
    /// supplying its own list must include the trusted issuer or construction
    /// throws (the OPRM-coherence invariant).
    /// </summary>
    public IReadOnlyList<string> AdvertisedAuthorizationServers { get; }

    public Uri? HttpBaseAddress { get; private set; }


    /// <summary>
    /// The resource server's own identity — the RFC 9728 §1.2 <c>resource</c>
    /// identifier the metadata document carries and the §3.3 resource-match
    /// validation compares against. Derived from the bound listener address
    /// once <see cref="StartHttpHostAsync"/> has run.
    /// </summary>
    public Uri? ResourceIdentity { get; private set; }


    /// <summary>
    /// The §3 path-inserted metadata URL derived from
    /// <see cref="ResourceIdentity"/> via
    /// <see cref="WellKnownPaths.OAuthProtectedResource"/>; the document is
    /// served here and every challenge advertises it through the §5.1
    /// <c>resource_metadata</c> parameter.
    /// </summary>
    public Uri? MetadataUrl { get; private set; }


    /// <summary>The self-signed leaf certificate the HTTPS listener presents once <see cref="StartHttpHostAsync"/> has run; callers pin to this via <see cref="LoopbackTls.CreatePinnedHttpClient(X509Certificate2, Uri?)"/>.</summary>
    public X509Certificate2? HttpCertificate { get; private set; }


    /// <summary>
    /// The shipped RS-side DPoP replay tracker (<see cref="InMemoryDpopReplayCache"/>). Tests inspect
    /// <see cref="InMemoryDpopReplayCache.Count"/> directly to verify replay-defense behaviour.
    /// </summary>
    public InMemoryDpopReplayCache ReplayCache { get; }


    /// <summary>
    /// Whether <c>/protected</c> always requires DPoP-bound access tokens, so a token presented under the
    /// <c>Bearer</c> scheme is refused with the <c>DPoP</c> challenge alone
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>,
    /// <c>dpop_bound_access_tokens_required</c>).
    /// </summary>
    public bool RequiresDpop { get; }


    /// <summary>
    /// Whether the resource server wires its DPoP proof validation, its nonce issuance and validation and its accepted
    /// algorithms into <see cref="Integration"/>; without them a DPoP-bound token is answered <c>server_error</c>. The
    /// <c>jti</c> record is wired apart from them, by <see cref="IsDpopProofJtiRecordWired"/>.
    /// </summary>
    public bool IsDpopProofValidationWired { get; }


    /// <summary>
    /// Whether the resource server wires the <c>jti</c> record, the seen query and the record of
    /// <see cref="ReplayCache"/>, into <see cref="Integration"/>; without them a DPoP-bound token is answered
    /// <c>server_error</c>.
    /// </summary>
    public bool IsDpopProofJtiRecordWired { get; }


    /// <summary>
    /// The scheme and authority the resource server names its own target URIs under, the configured origin a DPoP
    /// proof's <c>htu</c> is held to whatever <c>Host</c> a request names; <see langword="null"/> until
    /// <see cref="StartHttpHostAsync"/> sets it to the bound listener's origin, and settable after that so a row can
    /// configure another origin.
    /// </summary>
    public Uri? TargetAuthority { get; set; }


    /// <summary>
    /// Creates the resource server: its integration trusting <paramref name="trustedIssuer"/>'s tokens for
    /// <paramref name="expectedAudience"/>, its <c>jti</c> record over <see cref="ReplayCache"/> and its DPoP checks as
    /// the arguments wire them. The listener starts with <see cref="StartHttpHostAsync"/>.
    /// </summary>
    /// <param name="trustedIssuer">The issuer whose access tokens the resource accepts, among the advertised authorization servers.</param>
    /// <param name="expectedAudience">The audience the resource's access tokens name.</param>
    /// <param name="resolveVerificationKey">Resolves the issuer's access token verification key.</param>
    /// <param name="verifySignature">The signature verification access tokens and DPoP proofs are checked with.</param>
    /// <param name="timeProvider">The resource server's clock.</param>
    /// <param name="requiredScope">The scope a token must carry, or <see langword="null"/> for none.</param>
    /// <param name="advertisedAuthorizationServers">The <c>authorization_servers</c> the document advertises, or <see langword="null"/> for the trusted issuer alone.</param>
    /// <param name="requiresDpop">Whether <c>/protected</c> always requires DPoP-bound access tokens.</param>
    /// <param name="isDpopProofValidationWired">Whether the DPoP proof validation, the nonce slots and the accepted algorithms are wired.</param>
    /// <param name="isDpopProofJtiRecordWired">Whether the <c>jti</c> seen query and record are wired.</param>
    /// <param name="wrapDpopProofValidation">
    /// Wraps the wired DPoP proof validation, so a row can answer the library validator's result rewritten or wire a
    /// validation of its own in its place, or <see langword="null"/> to wire it as it is.
    /// </param>
    public TestResourceServerShell(
        Uri trustedIssuer,
        string expectedAudience,
        ServerVerificationKeyResolverDelegate resolveVerificationKey,
        VerificationDelegate verifySignature,
        TimeProvider timeProvider,
        string? requiredScope = null,
        IReadOnlyList<string>? advertisedAuthorizationServers = null,
        bool requiresDpop = false,
        bool isDpopProofValidationWired = true,
        bool isDpopProofJtiRecordWired = true,
        Func<ValidateDpopProofDelegate, ValidateDpopProofDelegate>? wrapDpopProofValidation = null)
    {
        ArgumentNullException.ThrowIfNull(trustedIssuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedAudience);
        ArgumentNullException.ThrowIfNull(resolveVerificationKey);
        ArgumentNullException.ThrowIfNull(verifySignature);
        ArgumentNullException.ThrowIfNull(timeProvider);

        IReadOnlyList<string> advertised = advertisedAuthorizationServers ?? [trustedIssuer.OriginalString];
        if(!advertised.Contains(trustedIssuer.OriginalString, StringComparer.Ordinal))
        {
            throw new ArgumentException(
                "OPRM coherence violated: the trusted issuer "
                + $"'{trustedIssuer.OriginalString}' is not among the advertised "
                + "authorization_servers. A resource server must accept tokens only "
                + "from an authorization server its RFC 9728 metadata document names.",
                nameof(advertisedAuthorizationServers));
        }

        VerifySignature = verifySignature;
        RequiredScope = requiredScope;
        AdvertisedAuthorizationServers = advertised;
        RequiresDpop = requiresDpop;
        IsDpopProofValidationWired = isDpopProofValidationWired;
        IsDpopProofJtiRecordWired = isDpopProofJtiRecordWired;
        ReplayCache = new InMemoryDpopReplayCache(timeProvider);
        NonceKeySet = CreateNonceKeySet();

        ResourceServerIntegration integration = new()
        {
            TrustedIssuer = trustedIssuer,
            ExpectedAudience = expectedAudience,
            ResolveVerificationKeyAsync = resolveVerificationKey,
            TimeProvider = timeProvider,
            IsDpopProofJtiSeenAsync = isDpopProofJtiRecordWired ? ReplayCache.IsSeenAsync : null,
            PersistDpopProofJtiAsync = isDpopProofJtiRecordWired ? ReplayCache.PersistAsync : null
        };
        Integration = isDpopProofValidationWired
            ? WireDpopChecks(integration, verifySignature, wrapDpopProofValidation ?? (static validate => validate))
            : integration;
    }


    /// <summary>
    /// The HMAC key set the resource server's nonces are issued and validated under, one current key; disposed with
    /// the shell.
    /// </summary>
    private InProcessKeySet NonceKeySet { get; }


    /// <summary>
    /// The resource server's DPoP slots over <paramref name="integration"/>: the proof validation
    /// <see cref="DpopProofValidator.ValidateAsync(DpopProofValidationRequest, VerificationDelegate, DpopJwsPartParser, EncodeDelegate, DecodeDelegate, TimeProvider, BaseMemoryPool, TimeSpan, CancellationToken)"/>
    /// over <paramref name="verifySignature"/>, with the integration's clock and its freshness window as the
    /// <c>iat</c> skew, as <see cref="TestHostShell.VerifyDpopProofsWithAsync"/> wires the authorization server's; the
    /// library's default nonce issuance and validation (<see cref="DefaultDpopNonceIssuance.IssueAsync"/>,
    /// <see cref="DefaultDpopNonceValidation.ValidateAsync"/>) over <see cref="NonceKeySet"/>; and the accepted
    /// algorithms <see cref="WellKnownDpopValues.SupportedSigningAlgorithms"/>.
    /// </summary>
    /// <param name="integration">The integration holding the trust, the clock and the <c>jti</c> record.</param>
    /// <param name="verifySignature">The signature verification every proof is checked with.</param>
    /// <param name="wrapDpopProofValidation">Wraps the proof validation before it is wired.</param>
    /// <returns>The integration with its DPoP slots wired.</returns>
    private ResourceServerIntegration WireDpopChecks(
        ResourceServerIntegration integration,
        VerificationDelegate verifySignature,
        Func<ValidateDpopProofDelegate, ValidateDpopProofDelegate> wrapDpopProofValidation)
    {
        TimeProvider timeProvider = integration.TimeProvider;
        TimeSpan iatSkew = integration.DpopFreshnessWindow;
        InProcessKeySet keySet = NonceKeySet;
        FillEntropyDelegate nonceEntropy = TestEntropy.NewCounterStream();

        return new ResourceServerIntegration
        {
            TrustedIssuer = integration.TrustedIssuer,
            ExpectedAudience = integration.ExpectedAudience,
            ResolveVerificationKeyAsync = integration.ResolveVerificationKeyAsync,
            TimeProvider = timeProvider,
            IsDpopProofJtiSeenAsync = integration.IsDpopProofJtiSeenAsync,
            PersistDpopProofJtiAsync = integration.PersistDpopProofJtiAsync,
            ValidateDpopProofAsync = wrapDpopProofValidation((request, ct) => DpopProofValidator.ValidateAsync(
                request, verifySignature, DpopTestSupport.Parser, TestSetup.Base64UrlEncoder, TestSetup.Base64UrlDecoder,
                timeProvider, BaseMemoryPool.Shared, iatSkew, ct)),
            IssueDpopNonceAsync = (audience, tenantId, ctx, ct) => DefaultDpopNonceIssuance.IssueAsync(
                audience, tenantId, ctx,
                (_, _, _) => ValueTask.FromResult(keySet.Snapshot()),
                selectHmacKey: null,
                (kid, _, _, _) => ValueTask.FromResult(keySet.ResolveMaterial(kid)),
                timeProvider, TestSetup.Base64UrlEncoder, nonceEntropy, BaseMemoryPool.Shared, ct),
            ValidateDpopNonceAsync = (presented, audience, tenantId, ctx, ct) => DefaultDpopNonceValidation.ValidateAsync(
                presented, audience, tenantId, ctx,
                (_, _, _) => ValueTask.FromResult(keySet.Snapshot()),
                (kid, _, _, _) => ValueTask.FromResult(keySet.ResolveMaterial(kid)),
                timeProvider, WellKnownDpopValues.DefaultNonceValidityWindow, TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared, ct),
            AcceptedDpopProofAlgorithms = WellKnownDpopValues.SupportedSigningAlgorithms
        };
    }


    /// <summary>
    /// Creates the HMAC key set the resource server's nonces are issued under: one current 256-bit HMAC-SHA-256 key whose
    /// octets come from the suite's deterministic entropy stream (<see cref="TestEntropy.NewCounterStream"/>).
    /// </summary>
    /// <returns>The key set; the shell disposes it.</returns>
    private static InProcessKeySet CreateNonceKeySet()
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(HmacKeyOctetCount);
        SymmetricKeyMemory? material = null;
        SymmetricKey? key = null;
        InProcessKeySet? keySet = null;
        try
        {
            TestEntropy.NewCounterStream()(owner.Memory.Span[..HmacKeyOctetCount]);
            material = new SymmetricKeyMemory(owner, CryptoTags.HmacSha256Key);
            key = new SymmetricKey(material, "resource-server-nonce-1", MicrosoftHmacFunctionsAdapter.ComputeHmacAsync, MicrosoftHmacFunctionsAdapter.VerifyHmacAsync);
            material = null;
            keySet = new InProcessKeySet();
            keySet.AddCurrent(new KeyId("resource-server-nonce-1"), key);
            key = null;
            InProcessKeySet created = keySet;
            keySet = null;

            return created;
        }
        finally
        {
            //Whatever was created and not handed on to its owner is released here: the key set owns the key, the key
            //its material, the material the rented octets.
            keySet?.Dispose();
            key?.Dispose();
            material?.Dispose();
        }
    }


    /// <summary>The octet count of the resource server's HMAC-SHA-256 nonce key.</summary>
    private static int HmacKeyOctetCount => 32;


    /// <summary>
    /// Starts the loopback HTTPS listener with a certificate of its own and the
    /// <see cref="ResourceServerHttpApplication"/> over <see cref="Integration"/>, then derives the resource identity
    /// and the metadata URL from the bound address, serves the RFC 9728 document there and sets
    /// <see cref="TargetAuthority"/> to the listener's origin unless a row set it. A second call does nothing.
    /// </summary>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A task that completes when the listener is bound.</returns>
    public async Task StartHttpHostAsync(CancellationToken cancellationToken = default)
    {
        if(webApplication is not null)
        {
            return;
        }

        //A test can stand up several resource-server shells side by side (RS1 and RS2 in a
        //multi-resource topology), so each shell needs a genuinely distinct TLS identity rather
        //than the process-wide shared leaf.
        X509Certificate2 certificate = LoopbackTls.CreateDistinctServerCertificate("resource-server-loopback-test-host");

        global::Microsoft.AspNetCore.Builder.WebApplicationBuilder builder =
            global::Microsoft.AspNetCore.Builder.WebApplication.CreateSlimBuilder();
        LoopbackKestrel.ConfigureLoopbackLogging(builder.Logging);

        //A single explicit HTTPS Listen call — no UseUrls — so there is no plaintext fallback on
        //this host at all.
        _ = builder.WebHost.ConfigureKestrel(options =>
            LoopbackKestrel.ConfigureLoopbackListener(options, certificate));

        global::Microsoft.AspNetCore.Builder.WebApplication app = builder.Build();

        ResourceServerHttpApplication application = new(Integration, VerifySignature, () => TargetAuthority, RequiredScope, RequiresDpop);
        app.Run(application.ProcessRequestAsync);

        await app.StartAsync(cancellationToken).ConfigureAwait(false);

        global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature addresses =
            app.Services.GetRequiredService<global::Microsoft.AspNetCore.Hosting.Server.IServer>()
                .Features.Get<global::Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()
            ?? throw new InvalidOperationException(
                "Kestrel started but no server addresses were exposed via IServerAddressesFeature.");
        string boundAddress = addresses.Addresses.FirstOrDefault()
            ?? throw new InvalidOperationException("Kestrel bound no address.");

        //The resource identity is the bound listener's origin: the same value
        //becomes the document's §1.2 resource identifier and the base the §3
        //well-known URL is inserted into, keeping the consumer's §3.3
        //resource-match validation true by construction.
        Uri baseAddress = new(boundAddress);
        Uri resourceIdentity = new(baseAddress.GetLeftPart(UriPartial.Authority));
        Uri metadataUrl = WellKnownPaths.OAuthProtectedResource.ComputeUri(resourceIdentity.OriginalString);

        metadataServer = await BuildMetadataServerAsync(resourceIdentity).ConfigureAwait(false);
        application.MetadataEndpoint = new ResourceServerMetadataEndpoint(metadataServer, metadataUrl);

        webApplication = app;
        HttpCertificate = certificate;
        HttpBaseAddress = baseAddress;
        ResourceIdentity = resourceIdentity;
        MetadataUrl = metadataUrl;
        TargetAuthority ??= resourceIdentity;
    }


    /// <summary>
    /// Composes the minimal <see cref="EndpointServer"/> that serves the
    /// RFC 9728 document: a single-tenant registration carrying only the
    /// <see cref="WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata"/>
    /// capability, default pipeline seams, and
    /// <see cref="ProtectedResourceMetadataEndpoints.Builder"/> as the sole
    /// endpoint builder. <c>resource</c> resolves from the registration's
    /// issuer (= <paramref name="resourceIdentity"/>) through the library's
    /// default issuer resolver; <c>authorization_servers</c>,
    /// <c>scopes_supported</c>, and <c>bearer_methods_supported</c> arrive
    /// through the
    /// <see cref="AuthorizationServerIntegration.ContributeProtectedResourceMetadataAsync"/>
    /// seam, exactly as an application would supply them.
    /// </summary>
    private async Task<EndpointServer> BuildMetadataServerAsync(Uri resourceIdentity)
    {
        ClientRecord registration = new()
        {
            ClientId = resourceIdentity.OriginalString,
            TenantId = new TenantId("resource-server"),
            IssuerUri = resourceIdentity,
            AllowedCapabilities = ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthProtectedResourceMetadata),
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet<string>.Empty,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty,
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty
        };

        IReadOnlyList<string> advertisedAuthorizationServers = AdvertisedAuthorizationServers;
        string? requiredScope = RequiredScope;

        AuthorizationServerIntegration integration = new()
        {
            ExtractTenantIdAsync = (ctx, ct) =>
                ValueTask.FromResult<TenantId?>(registration.TenantId),

            LoadClientRegistrationAsync = (tenantId, ctx, ct) =>
                ValueTask.FromResult<IRegistrationRecord?>(registration),

            //Stateless metadata dispatch never persists flow state; the seams
            //are wired because Validate requires them for any host.
            SaveFlowStateAsync = (tenantId, flowId, state, stepCount, ctx, ct) =>
                ValueTask.CompletedTask,
            //The (FlowState?) cast is load-bearing: ValueTask.FromResult<TResult> infers TResult from
            //the argument alone, and a bare null here has no natural type to give the tuple a
            //(FlowState?, int) shape at all.
            LoadFlowStateAsync = (tenantId, flowId, ctx, ct) =>
                ValueTask.FromResult(((FlowState?)null, 0)),
            //Stateless metadata dispatch never claims a flow; wired only to satisfy Validate().
            ClaimFlowStateAsync = (tenantId, flowId, expectedStepCount, ctx, ct) =>
                ValueTask.FromResult(true),
            //A claim that holds no mark has none to remove; wired only to satisfy Validate().
            ReleaseFlowStateAsync = (tenantId, flowId, expectedStepCount, ctx, ct) =>
                ValueTask.CompletedTask,
            //Stateless metadata dispatch never deletes a flow record either; wired only to satisfy
            //AuthorizationServerIntegration.Validate(), which requires it unconditionally for the
            //Authorization Code lifecycle's revocation paths even though this resource-server-only
            //host never runs them.
            DeleteFlowStateAsync = (tenantId, flowId, ctx, ct) =>
                ValueTask.CompletedTask,
            //Stateless metadata dispatch never reads a grant either; wired only to satisfy
            //AuthorizationServerIntegration.Validate() for the same reason as DeleteFlowStateAsync
            //above.
            LoadGrantFlowStatesAsync = (tenantId, grantFlowId, ctx, ct) =>
                ValueTask.FromResult<IReadOnlyList<(string FlowId, FlowState State, int StepCount)>>([]),

            ResolvePolicyAsync = (reg, ctx, ct) =>
                PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)reg, ctx, ct),
            ResolveCapabilitiesAsync = DefaultCapabilityResolver.ResolveAsync,
            InspectAsync = DefaultInspector.NoOpAsync,
            GenerateIdentifierAsync = DefaultIdentifierGenerator.For(Integration.TimeProvider, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared),
            ResolveSubjectIdentifierAsync = DefaultSubjectIdentifierResolver.PublicAsync,

            //RFC 9728 §3: the metadata URL is formed by inserting the
            //well-known suffix into the resource identifier; WellKnownPaths
            //owns that computation for the one endpoint this host serves.
            ResolveEndpointUriAsync = (endpointKey, reg, ctx, ct) =>
                ValueTask.FromResult<Uri?>(
                    string.Equals(endpointKey, WellKnownEndpointNames.ProtectedResourceMetadata, StringComparison.Ordinal)
                        ? WellKnownPaths.OAuthProtectedResource.ComputeUri(resourceIdentity.OriginalString)
                        : null),

            ContributeProtectedResourceMetadataAsync = (reg, ctx, ct) =>
                ValueTask.FromResult(new ProtectedResourceMetadataContribution
                {
                    AuthorizationServers = advertisedAuthorizationServers,
                    ScopesSupported = requiredScope is not null ? [requiredScope] : null,
                    BearerMethodsSupported = [BearerMethodValues.Header]
                }),
            Cryptography = new AuthorizationServerCryptography
            {
                SigningKeyResolver = (_, _, _, _) => ValueTask.FromResult<PrivateKeyMemory?>(null),
                VerificationKeyResolver = (_, _, _, _, _) => ValueTask.FromResult<PublicKeyMemory?>(null)
            },
            Codecs = new AuthorizationServerCodecs
            {
                Encoder = TestSetup.Base64UrlEncoder,
                Decoder = TestSetup.Base64UrlDecoder,
                ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
                JwtHeaderSerializer = static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
                    (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions),
                JwtPayloadSerializer = static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
                    (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions),
                JwtHeaderDeserializer = static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                    bytes, TestSetup.DefaultSerializationOptions) ?? throw new FormatException("Header JSON parsed to null."),
                JwtPayloadDeserializer = static bytes => JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
                    bytes, TestSetup.DefaultSerializationOptions) ?? throw new FormatException("Payload JSON parsed to null.")
            },
            MemoryPool = BaseMemoryPool.Shared
        };

        EndpointServer server = new()
        {
            Integration = integration,
            TimeProvider = Integration.TimeProvider,
            Configuration = new ServerConfiguration
            {
                EndpointBuilders = new EndpointBuilderSet(
                [
                    ProtectedResourceMetadataEndpoints.Builder
                ])
            }
        };

        server.AddIntegration(integration);
        await server.RequestAlterationAsync(_ => { }).ConfigureAwait(false);

        return server;
    }


    public async ValueTask DisposeAsync()
    {
        if(Disposed)
        {
            return;
        }

        Disposed = true;

        if(webApplication is not null)
        {
            await webApplication.StopAsync(CancellationToken.None).ConfigureAwait(false);
            await webApplication.DisposeAsync().ConfigureAwait(false);
            webApplication = null;
        }

        metadataServer?.Dispose();
        metadataServer = null;

        NonceKeySet.Dispose();
        HttpCertificate?.Dispose();
    }
}
