using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Describes one active HTTP endpoint for a client registration, encoding everything
/// the <see cref="AuthorizationServerDispatcher"/> needs to process a request.
/// </summary>
/// <remarks>
/// <para>
/// The dispatcher finds the matching endpoint by path and HTTP method, then drives
/// it in order:
/// </para>
/// <list type="number">
///   <item><description><see cref="Kind"/> — provides <see cref="FlowKind.Create"/> and <see cref="FlowKind.Step"/> for the flow.</description></item>
///   <item><description><see cref="BuildInputAsync"/> — validates fields, performs effectful work, returns the PDA input.</description></item>
///   <item><description><see cref="BuildResponse"/> — turns the resulting state into an HTTP response.</description></item>
/// </list>
/// <para>
/// The ASP.NET skin loop is identical for every endpoint and every flow — a single
/// catch-all route delegates everything to
/// <see cref="AuthorizationServerDispatcher.DispatchAsync"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerEndpoint {HttpMethod} {PathTemplate} Capability={Capability} StartsNewFlow={StartsNewFlow}")]
public sealed record ServerEndpoint
{
    /// <summary>The HTTP method. One of <c>GET</c> or <c>POST</c>.</summary>
    public required string HttpMethod { get; init; }

    /// <summary>
    /// The path template from <see cref="ServerEndpointPaths"/>, e.g.
    /// <c>/connect/{segment}/par</c>. Pass directly to the routing framework.
    /// </summary>
    public required string PathTemplate { get; init; }

    /// <summary>The capability this endpoint serves.</summary>
    public required ServerCapabilityName Capability { get; init; }

    /// <summary>
    /// The flow kind this endpoint belongs to. Provides <see cref="FlowKind.Create"/>
    /// for new flows and <see cref="FlowKind.Step"/> for continuing flows.
    /// Use <see cref="FlowKind.Stateless"/> for endpoints that serve computed
    /// responses without session state — JWKS, discovery, and similar metadata endpoints.
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
    /// Whether this is a global endpoint not scoped to a specific client registration.
    /// </summary>
    public bool IsGlobal { get; init; }

    /// <summary>
    /// An optional predicate that refines endpoint selection beyond path and HTTP method.
    /// When <see langword="null"/> the endpoint matches any request reaching its path
    /// and method. When set, the dispatcher calls it with the request fields and only
    /// selects this endpoint if it returns <see langword="true"/>.
    /// </summary>
    /// <remarks>
    /// Use when two endpoints share the same path and method but serve different
    /// request shapes — for example, the PAR-backed authorize endpoint (which requires
    /// a <c>request_uri</c> field) and the direct authorize endpoint (which must not
    /// have a <c>request_uri</c> field) both map to
    /// <c>GET /connect/{segment}/authorize</c>.
    /// </remarks>
    public Func<RequestFields, bool>? MatchesRequest { get; init; }

    /// <summary>
    /// An optional delegate that extracts the correlation key for this endpoint.
    /// When <see langword="null"/> the dispatcher uses its built-in cascade
    /// (<c>request_uri</c>, <c>code</c>, <c>device_code</c>, <c>state</c>,
    /// then context bag fallback).
    /// </summary>
    /// <remarks>
    /// Set this on endpoints whose correlation key pattern differs from the standard
    /// OAuth handles — for example CIBA endpoints that use <c>auth_req_id</c>, or
    /// custom flows with application-specific identifiers.
    /// </remarks>
    public ExtractCorrelationKeyDelegate? ExtractCorrelationKey { get; init; }

    /// <summary>
    /// Validates fields, performs effectful work, and returns the input to step
    /// the PDA with — or an early-exit response if validation fails.
    /// </summary>
    public required BuildInputDelegate BuildInputAsync { get; init; }

    /// <summary>
    /// Builds the HTTP response from the state the PDA landed in after a successful
    /// step. Receives the resulting state and the flow kind name for logging.
    /// </summary>
    public required BuildResponseDelegate BuildResponse { get; init; }
}
