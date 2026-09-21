using Verifiable.Cryptography.Text;


namespace Verifiable.Server.Diagnostics;

/// <summary>
/// Span event names emitted during protocol-neutral endpoint host dispatch operations.
/// </summary>
/// <remarks>
/// <para>
/// Events are points in time within a span. Host dispatch events capture the dispatch
/// loop milestones: flow creation, correlation resolution outcomes, and PDA state transitions.
/// </para>
/// </remarks>
public static class ServerEventNames
{
    /// <summary>The UTF-8 source literal of <see cref="StateTransition"/>.</summary>
    public static ReadOnlySpan<byte> StateTransitionUtf8 => "server.flow.state_transition"u8;

    /// <summary>
    /// The PDA transitioned to a new state.
    /// </summary>
    public static string StateTransition { get; } = Utf8Constants.ToInternedString(StateTransitionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CorrelationResolved"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationResolvedUtf8 => "server.correlation.resolved"u8;

    /// <summary>
    /// The correlation key was resolved from an external handle to the
    /// internal flow identifier.
    /// </summary>
    public static string CorrelationResolved { get; } = Utf8Constants.ToInternedString(CorrelationResolvedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CorrelationNotFound"/>.</summary>
    public static ReadOnlySpan<byte> CorrelationNotFoundUtf8 => "server.correlation.not_found"u8;

    /// <summary>
    /// The correlation key could not be resolved — flow not found.
    /// </summary>
    public static string CorrelationNotFound { get; } = Utf8Constants.ToInternedString(CorrelationNotFoundUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FlowCreated"/>.</summary>
    public static ReadOnlySpan<byte> FlowCreatedUtf8 => "server.flow.created"u8;

    /// <summary>
    /// A new flow was created with a fresh internal flow identifier.
    /// </summary>
    public static string FlowCreated { get; } = Utf8Constants.ToInternedString(FlowCreatedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NoMatch"/>.</summary>
    public static ReadOnlySpan<byte> NoMatchUtf8 => "server.dispatch.no_match"u8;

    /// <summary>
    /// The dispatcher answered a request with no matched endpoint. Carries
    /// <see cref="NoMatchCategoryTagName"/> naming the reason from
    /// <see cref="NoMatchCategories"/>, plus, when the chain was built,
    /// <see cref="NoMatchCandidateCountTagName"/>, <see cref="NoMatchCapabilityFilteredTagName"/>,
    /// <see cref="NoMatchEndpointNameUnresolvedTagName"/> and <see cref="NoMatchDeclinedTagName"/>. Recorded only on the dispatch
    /// <see cref="System.Diagnostics.Activity"/>, never in the response body, which
    /// stays <see cref="Verifiable.Server.ServerHttpResponse.NotFound()"/>'s empty shape.
    /// </summary>
    public static string NoMatch { get; } = Utf8Constants.ToInternedString(NoMatchUtf8);

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key on a
    /// <see cref="NoMatch"/> event carrying the reason, one of the
    /// <see cref="NoMatchCategories"/> constants.
    /// </summary>
    public static string NoMatchCategoryTagName { get; } = "server.dispatch.no_match_category";

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key on a
    /// <see cref="NoMatch"/> event carrying the number of endpoint candidates the
    /// dispatcher walked before answering no match.
    /// </summary>
    public static string NoMatchCandidateCountTagName { get; } = "server.dispatch.no_match_candidate_count";

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key on a
    /// <see cref="NoMatch"/> event carrying the space-separated endpoint names the
    /// per-request capability filter removed from the chain.
    /// </summary>
    public static string NoMatchCapabilityFilteredTagName { get; } = "server.dispatch.no_match_capability_filtered";

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key on a
    /// <see cref="NoMatch"/> event carrying the space-separated endpoint names whose
    /// matcher declined the request.
    /// </summary>
    public static string NoMatchDeclinedTagName { get; } = "server.dispatch.no_match_declined";

    /// <summary>
    /// The <see cref="System.Diagnostics.ActivityTagsCollection"/> key on a
    /// <see cref="NoMatch"/> event carrying the space-separated endpoint names whose
    /// <see cref="Verifiable.Server.ServerIntegration.ResolveEndpointUriAsync"/> call answered
    /// <see langword="null"/>.
    /// </summary>
    public static string NoMatchEndpointNameUnresolvedTagName { get; } = "server.dispatch.no_match_endpoint_name_unresolved";
}
