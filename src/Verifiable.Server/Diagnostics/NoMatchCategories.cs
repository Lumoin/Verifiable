using Verifiable.Server.Pipeline;

namespace Verifiable.Server.Diagnostics;

/// <summary>
/// The reasons <see cref="Verifiable.Server.EndpointServer"/> answers a request with no matched
/// endpoint, carried as the <see cref="ServerEventNames.NoMatchCategoryTagName"/> value on the
/// <see cref="ServerEventNames.NoMatch"/> event.
/// </summary>
/// <remarks>
/// <see cref="Verifiable.Server.ServerHttpResponse.NotFound()"/> carries an empty body, so an
/// operator reading only the response cannot tell an unregistered tenant from a route this
/// registration's active capabilities do not allow from a request no matcher in the chain
/// accepted. These constants are the vocabulary the dispatch <see cref="System.Diagnostics.Activity"/>
/// uses to say which.
/// </remarks>
public static class NoMatchCategories
{
    /// <summary>
    /// No <see cref="Verifiable.Server.IRegistrationRecord"/> exists for the resolved tenant, so
    /// <see cref="EndpointChain.BuildForRequestAsync"/> never ran.
    /// </summary>
    public static string NoRegistrationForTenant { get; } = "no_registration_for_tenant";

    /// <summary>
    /// No endpoint builder produced a candidate for this registration and request, and the
    /// capability filter removed nothing — nothing in this configuration serves the path at all.
    /// </summary>
    public static string NoCandidateForPathAndMethod { get; } = "no_candidate_for_path_and_method";

    /// <summary>
    /// Every candidate a builder produced for this request was removed because the registration's
    /// active capability set — <see cref="Verifiable.Server.ServerIntegration.ResolveCapabilitiesAsync"/> —
    /// did not allow it, leaving the chain <see cref="EndpointChain.MatchAsync"/> walks empty.
    /// </summary>
    public static string CapabilityFiltered { get; } = "capability_filtered";

    /// <summary>
    /// At least one candidate survived the capability filter into the chain, but every one declined
    /// the request in its own <see cref="Verifiable.Server.ServerEndpoint.MatchesRequest"/>.
    /// </summary>
    public static string MatcherDeclined { get; } = "matcher_declined";

    /// <summary>
    /// At least one candidate survived the capability filter, but
    /// <see cref="Verifiable.Server.ServerIntegration.ResolveEndpointUriAsync"/> answered
    /// <see langword="null"/> for its <see cref="Verifiable.Server.EndpointCandidate.Name"/>, so the
    /// candidate never entered the chain <see cref="EndpointChain.MatchAsync"/> walks.
    /// </summary>
    public static string EndpointNameUnresolved { get; } = "endpoint_name_unresolved";
}
