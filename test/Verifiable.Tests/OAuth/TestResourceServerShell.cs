using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.OAuth;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;
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

    /// <summary>The self-signed leaf certificate the HTTPS listener presents once <see cref="StartHttpHostAsync"/> has run; callers pin to this via <see cref="LoopbackTls.CreatePinnedHttpClient"/>.</summary>
    public X509Certificate2? HttpCertificate { get; private set; }

    /// <summary>
    /// Per-request DPoP proof JTI tracker. Maps jti → expiry instant. Tests inspect
    /// this directly to verify replay-defense behaviour.
    /// </summary>
    public ConcurrentDictionary<string, DateTimeOffset> SeenDpopJtis { get; } =
        new(StringComparer.Ordinal);


    public TestResourceServerShell(
        Uri trustedIssuer,
        string expectedAudience,
        ServerVerificationKeyResolverDelegate resolveVerificationKey,
        VerificationDelegate verifySignature,
        TimeProvider timeProvider,
        string? requiredScope = null,
        IReadOnlyList<string>? advertisedAuthorizationServers = null)
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

        Integration = new ResourceServerIntegration
        {
            TrustedIssuer = trustedIssuer,
            ExpectedAudience = expectedAudience,
            ResolveVerificationKeyAsync = resolveVerificationKey,
            TimeProvider = timeProvider,
            IsDpopProofJtiSeenAsync = (jti, ctx, ct) =>
                ValueTask.FromResult(SeenDpopJtis.ContainsKey(jti)),
            PersistDpopProofJtiAsync = (jti, expiresAt, ctx, ct) =>
            {
                SeenDpopJtis[jti] = expiresAt;
                return ValueTask.CompletedTask;
            }
        };
    }


    public async Task StartHttpHostAsync(CancellationToken cancellationToken = default)
    {
        if(webApplication is not null)
        {
            return;
        }

        X509Certificate2 certificate = LoopbackTls.CreateServerCertificate("resource-server-loopback-test-host");

        global::Microsoft.AspNetCore.Builder.WebApplicationBuilder builder =
            global::Microsoft.AspNetCore.Builder.WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();

        //A single explicit HTTPS Listen call — no UseUrls — so there is no plaintext fallback on
        //this host at all.
        builder.WebHost.ConfigureKestrel(options =>
            options.Listen(IPAddress.Loopback, port: 0, listenOptions => listenOptions.UseHttps(certificate)));

        global::Microsoft.AspNetCore.Builder.WebApplication app = builder.Build();

        ResourceServerHttpApplication application = new(Integration, VerifySignature, RequiredScope);
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

        metadataServer = BuildMetadataServer(resourceIdentity);
        application.MetadataEndpoint = new ResourceServerMetadataEndpoint(metadataServer, metadataUrl);

        webApplication = app;
        HttpCertificate = certificate;
        HttpBaseAddress = baseAddress;
        ResourceIdentity = resourceIdentity;
        MetadataUrl = metadataUrl;
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
    private EndpointServer BuildMetadataServer(Uri resourceIdentity)
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
            LoadFlowStateAsync = (tenantId, flowId, ctx, ct) =>
                ValueTask.FromResult(((FlowState?)null, 0)),

            ResolvePolicyAsync = (reg, ctx, ct) =>
                PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)reg, ctx, ct),
            ResolveCapabilitiesAsync = DefaultCapabilityResolver.ResolveAsync,
            InspectAsync = DefaultInspector.NoOpAsync,
            GenerateIdentifierAsync = DefaultIdentifierGenerator.ForTimeProvider(Integration.TimeProvider),
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
                })
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
        server.Validate();

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

        HttpCertificate?.Dispose();
    }
}
