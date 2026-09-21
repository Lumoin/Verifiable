using System.Diagnostics;
using Verifiable.Server.Routing;

namespace Verifiable.Server;

/// <summary>
/// A builder's pre-URI-resolution view of an endpoint. Builders construct
/// <see cref="EndpointCandidate"/> instances; <see cref="Pipeline.EndpointChain"/>
/// filters them by the per-request capability set and projects each survivor
/// to a complete <see cref="ServerEndpoint"/> after calling
/// <see cref="ServerIntegration.ResolveEndpointUriAsync"/> to
/// attach a <see cref="ServerEndpoint.ResolvedUri"/>.
/// </summary>
/// <remarks>
/// The split exists so the per-call URL (which only the application knows
/// how to compute) can be a non-nullable property on <see cref="ServerEndpoint"/>
/// without forcing builders to invent placeholder URIs. Candidates carry the
/// stable role identity (<see cref="Name"/>) the resolver lambda switches on.
/// </remarks>
[DebuggerDisplay("Candidate {Name,nq} Capability={Capability}")]
public sealed record EndpointCandidate
{
    /// <summary>
    /// Stable endpoint role identifier. See
    /// <c>WellKnownEndpointNames</c> for the library's catalogue.
    /// </summary>
    public required string Name { get; init; }

    /// <summary>
    /// Capability this endpoint serves. Used by the chain build to filter
    /// candidates against the per-request capability set returned by
    /// <see cref="ServerIntegration.ResolveCapabilitiesAsync"/>.
    /// </summary>
    public required CapabilityIdentifier Capability { get; init; }

    /// <summary>
    /// HTTP method this endpoint serves. Descriptive metadata only — matchers
    /// test the method inside <see cref="MatchesRequest"/>.
    /// </summary>
    public required string HttpMethod { get; init; }

    /// <summary>
    /// Flow kind this endpoint belongs to.
    /// </summary>
    public required FlowKind Kind { get; init; }

    /// <summary>
    /// Whether this endpoint starts a new flow session.
    /// </summary>
    public required bool StartsNewFlow { get; init; }

    /// <summary>
    /// The matcher that decides whether this endpoint accepts the inbound
    /// request. See <see cref="ServerEndpoint.MatchesRequest"/> for the
    /// disjointness invariant and acceptance-test discipline.
    /// </summary>
    public required MatchRequestDelegate MatchesRequest { get; init; }

    /// <summary>
    /// Validates fields, performs effectful work, and returns the input to
    /// step the PDA with — or an early-exit response.
    /// </summary>
    public required BuildInputDelegate BuildInputAsync { get; init; }

    /// <summary>
    /// Builds the HTTP response from the state the PDA landed in.
    /// </summary>
    public required BuildResponseDelegate BuildResponse { get; init; }

    /// <summary>
    /// The endpoint's own pre-correlation check. See
    /// <see cref="ServerEndpoint.BeforeCorrelationAsync"/> and
    /// <see cref="BeforeCorrelationDelegate"/> for the full remarks.
    /// <see langword="null"/> (the default) runs no such check for this
    /// candidate.
    /// </summary>
    public BeforeCorrelationDelegate? BeforeCorrelationAsync { get; init; }

    /// <summary>
    /// Optional correlation-key extractor for endpoints whose handle pattern
    /// differs from the standard OAuth handles. See
    /// <see cref="ServerEndpoint.ExtractCorrelationKey"/>.
    /// </summary>
    public ExtractCorrelationKeyDelegate? ExtractCorrelationKey { get; init; }

    /// <summary>
    /// The discovery-document field name to publish this endpoint's
    /// <see cref="ServerEndpoint.ResolvedUri"/> under (e.g.
    /// <c>token_endpoint</c>, <c>jwks_uri</c>). <see langword="null"/> for
    /// endpoints that are not advertised in discovery.
    /// </summary>
    public string? DiscoveryMetadataKey { get; init; }

    /// <summary>
    /// The OAuth 2.0 error code this endpoint's handler returns when its correlation handle — a
    /// <c>code</c>, <c>request_uri</c>, or similar continuation token — resolves to no live flow:
    /// unknown, expired, or already consumed. Read by <see cref="EndpointServer"/> at every
    /// "handle not found" refusal site in <c>HandleCoreAsync</c>. <see langword="null"/> falls back
    /// to the host-generic <see cref="ServerErrors.InvalidRequest"/> vocabulary — correct for an
    /// endpoint whose handle carries no protocol-specific error semantics of its own.
    /// </summary>
    /// <remarks>
    /// The token endpoint's authorization code is the motivating case:
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see> defines
    /// <c>invalid_grant</c> as "the provided authorization grant ... is invalid, expired, revoked
    /// ..." — exactly the three refusals this property governs.
    /// </remarks>
    public string? HandleNotFoundError { get; init; }

    /// <summary>
    /// The <c>error_description</c> paired with <see cref="HandleNotFoundError"/>.
    /// <see langword="null"/> falls back to the host-generic description.
    /// </summary>
    public string? HandleNotFoundErrorDescription { get; init; }

    /// <summary>
    /// The <c>invalid_request</c> description this endpoint's handler answers when
    /// <see cref="ExtractCorrelationKey"/> — or the standard field it stands in for — yields no
    /// handle at all, naming the missing parameter this endpoint alone knows. <see langword="null"/>
    /// falls back to <see cref="EndpointServer"/>'s host-generic description.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2</see> defines
    /// <c>invalid_request</c> as "the request is missing a required parameter" — a description that
    /// names the parameter, in the style of the endpoint's own "Missing grant_type." and "Missing
    /// response_type." refusals, is more useful than the host's generic "Cannot determine correlation
    /// key." to a caller who does not know this endpoint keys its continuing flow on that field.
    /// </remarks>
    public string? MissingCorrelationKeyErrorDescription { get; init; }
}
