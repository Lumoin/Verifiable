using System.Diagnostics;

using Verifiable.OAuth.Server.Routing;
namespace Verifiable.OAuth.Server;

/// <summary>
/// Describes one active endpoint for a client registration, encoding everything
/// the <see cref="AuthorizationServer"/> needs to process a request: the
/// matcher that decides whether the endpoint accepts a given request, the
/// flow machinery that processes it, and descriptive metadata for telemetry
/// and discovery.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Routing model.</strong>
/// The library owns routing end-to-end. The application skin produces a
/// typed <see cref="IncomingRequest"/> and hands it to
/// <see cref="AuthorizationServer.DispatchAsync(IncomingRequest, CancellationToken)"/>;
/// the library walks the per-registration <see cref="EndpointChain"/> and
/// invokes each endpoint's <see cref="MatchesRequest"/> in order. The first
/// matcher to return non-<see langword="null"/> wins.
/// </para>
/// <para>
/// The chain walk does not pre-filter on <see cref="HttpMethod"/> or
/// <see cref="Capability"/>. Each matcher's body declares its own
/// acceptance test — path checks, method checks, body field checks,
/// header checks, registration-capability checks. Reading the matcher
/// tells you exactly what requests it accepts; reading the chain tells
/// you what the server accepts for a registration.
/// </para>
/// <para>
/// <strong>Metadata role of <see cref="HttpMethod"/> and <see cref="Capability"/>.</strong>
/// Both fields are descriptive metadata, not routing inputs. Discovery
/// document generation, structural-query helpers, and post-match telemetry
/// (the dispatcher places the matched endpoint's <see cref="Capability"/>
/// on <see cref="RequestContext"/> after the match wins) consume them. The
/// matcher itself is responsible for whatever method-and-capability gating
/// its acceptance test requires.
/// </para>
/// <para>
/// Per-endpoint URL composition — what to put in the <c>request_uri</c>
/// response of PAR, the <c>jwks_uri</c> field of the discovery document,
/// the <c>iss</c> claim of issued tokens — happens through
/// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>,
/// answered by the application.
/// </para>
/// <para>
/// The dispatcher drives a matched endpoint in order:
/// </para>
/// <list type="number">
///   <item><description><see cref="Kind"/> — provides <see cref="FlowKind.Create"/> and <see cref="FlowKind.Step"/> for the flow.</description></item>
///   <item><description><see cref="BuildInputAsync"/> — validates fields, performs effectful work, returns the PDA input.</description></item>
///   <item><description><see cref="BuildResponse"/> — turns the resulting state into an HTTP response.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("ServerEndpoint {Name,nq} {HttpMethod,nq} Capability={Capability}")]
public sealed record ServerEndpoint
{
    /// <summary>
    /// A short stable identifier for this endpoint, used for telemetry tags,
    /// trace records, and structural-query helpers. Convention:
    /// <c>Family.Endpoint</c> in PascalCase, e.g. <c>AuthCode.Par</c>,
    /// <c>Oid4Vp.JarRequest</c>, <c>Metadata.Discovery</c>.
    /// </summary>
    /// <remarks>
    /// Required because the chain walk's disjointness assertion and the
    /// post-match telemetry record both need a way to identify which
    /// matcher won, and "the endpoint at index 3 in this chain" is not a
    /// stable identifier across reconfiguration.
    /// </remarks>
    public required string Name { get; init; }

    /// <summary>
    /// The HTTP method this endpoint serves. Descriptive metadata only —
    /// the chain walk does not filter on it; matchers test method
    /// themselves inside <see cref="MatchesRequest"/>. Used by discovery
    /// generation and telemetry.
    /// </summary>
    public required string HttpMethod { get; init; }

    /// <summary>
    /// The capability this endpoint serves. Descriptive metadata only —
    /// the chain walk does not filter on it. The dispatcher places the
    /// matched endpoint's capability on <see cref="RequestContext"/>
    /// after the match wins for post-match telemetry and observability.
    /// Used by discovery generation, structural-query helpers, and the
    /// per-registration capability advertisement.
    /// </summary>
    public required ServerCapabilityName Capability { get; init; }

    /// <summary>
    /// The flow kind this endpoint belongs to. Provides <see cref="FlowKind.Create"/>
    /// for new flows and <see cref="FlowKind.Step"/> for continuing flows.
    /// Use <see cref="FlowKind.Stateless"/> for endpoints that serve computed
    /// responses without session state — JWKS, discovery, and similar metadata
    /// endpoints.
    /// </summary>
    public required FlowKind Kind { get; init; }

    /// <summary>
    /// Whether this endpoint starts a new flow session. When <see langword="true"/>
    /// the dispatcher calls <see cref="FlowKind.Create"/>. When <see langword="false"/>
    /// it loads persisted state and calls <see cref="FlowKind.Step"/>.
    /// Stateless endpoints set this to <see langword="true"/> and use
    /// <see cref="FlowKind.Stateless"/> — <see cref="ServerEndpoint.BuildInputAsync"/>
    /// returns an early-exit response before the PDA is ever stepped or persisted.
    /// </summary>
    public required bool StartsNewFlow { get; init; }

    /// <summary>
    /// The matcher that decides whether this endpoint accepts the inbound
    /// request, returning a typed <see cref="MatchPayload"/> when it accepts
    /// or <see langword="null"/> when it does not.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Required. Every endpoint declares its acceptance test explicitly:
    /// path checks, method checks, body field checks, header checks, and
    /// registration-capability checks all live inside the matcher body.
    /// The chain walk does not pre-filter; the matcher's body is the
    /// complete acceptance test.
    /// </para>
    /// <para>
    /// Endpoints whose acceptance is fully expressed by their non-null
    /// return — i.e. they have no classification data to hand to their
    /// handler — return <see cref="MatchPayload.Empty"/>. Endpoints whose
    /// matchers classify the request (token shape, header presence, parsed
    /// payload) return their endpoint-specific <see cref="MatchPayload"/>
    /// subtype, which the dispatcher places on
    /// <see cref="RequestContext"/> via
    /// <see cref="RequestContextExtensions.SetMatchPayload"/> for the
    /// handler to read.
    /// </para>
    /// <para>
    /// <strong>Disjointness.</strong> Within a single registration's chain,
    /// at most one matcher must accept any given request. Endpoints that
    /// share path-and-method (the PAR-three-flavors case being the
    /// canonical example) gate their acceptance on body-field signatures
    /// or registration-capability presence so that the chain remains
    /// disjoint. The chain walk debug-asserts this invariant in DEBUG
    /// builds.
    /// </para>
    /// <para>
    /// See <see cref="MatchRequestDelegate"/> for the cancellation,
    /// hostile-input, and cheap-signals-first requirements.
    /// </para>
    /// </remarks>
    public required MatchRequestDelegate MatchesRequest { get; init; }

    /// <summary>
    /// An optional delegate that extracts the correlation key for this endpoint.
    /// When <see langword="null"/> the dispatcher reads the correlation key from
    /// <see cref="RequestContextExtensions.CorrelationKey"/> on the request
    /// context.
    /// </summary>
    /// <remarks>
    /// Set this on endpoints whose correlation key pattern differs from the
    /// standard OAuth handles — for example CIBA endpoints that use
    /// <c>auth_req_id</c>, or custom flows with application-specific identifiers.
    /// </remarks>
    public ExtractCorrelationKeyDelegate? ExtractCorrelationKey { get; init; }

    /// <summary>
    /// Validates fields, performs effectful work, and returns the input to step
    /// the PDA with — or an early-exit response if validation fails.
    /// </summary>
    public required BuildInputDelegate BuildInputAsync { get; init; }

    /// <summary>
    /// Builds the HTTP response from the state the PDA landed in after a
    /// successful step. Receives the resulting state and the flow kind name for
    /// logging.
    /// </summary>
    public required BuildResponseDelegate BuildResponse { get; init; }

    /// <summary>
    /// The per-request absolute URL this endpoint is reachable at, computed
    /// by <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/> via
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// once per request. Matchers compare the inbound path against
    /// <see cref="Uri.AbsolutePath"/> rather than carrying path templates
    /// themselves; discovery emission reads it for the
    /// <see cref="DiscoveryMetadataKey"/> field publication.
    /// </summary>
    /// <remarks>
    /// Phase 9h interim: nullable while builders still construct
    /// <see cref="ServerEndpoint"/> directly. Tightens to <c>required</c>
    /// in chunk 8 when <see cref="Pipeline.EndpointChain.BuildForRequestAsync"/>
    /// becomes the sole construction site.
    /// </remarks>
    public Uri? ResolvedUri { get; init; }

    /// <summary>
    /// The discovery-document field name under which this endpoint's
    /// <see cref="ResolvedUri"/> is published (e.g. <c>token_endpoint</c>,
    /// <c>jwks_uri</c>). <see langword="null"/> for endpoints that do not
    /// appear in discovery.
    /// </summary>
    public string? DiscoveryMetadataKey { get; init; }
}
