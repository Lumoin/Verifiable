using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Convenience methods for resolving a <see cref="ServerEndpoint"/> from a list
/// by HTTP method and capability.
/// </summary>
/// <remarks>
/// <para>
/// The library does not own routing. The application maps its routes to endpoints
/// however it wants. This class provides optional helpers for applications and
/// tests that resolve endpoints by matching criteria against the endpoint list
/// returned by <see cref="AuthorizationServer.GetEndpoints"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("EndpointMatcher")]
public static class EndpointMatcher
{
    /// <summary>
    /// Finds the first endpoint matching the given capability and HTTP method.
    /// </summary>
    /// <param name="endpoints">The endpoint list from <see cref="AuthorizationServer.GetEndpoints"/>.</param>
    /// <param name="capability">The capability to match.</param>
    /// <param name="httpMethod">The HTTP method to match.</param>
    /// <param name="startsNewFlow">Whether the endpoint must start a new flow.</param>
    /// <returns>
    /// The matching endpoint, or <see langword="null"/> if no endpoint matches.
    /// </returns>
    public static ServerEndpoint? Find(
        IReadOnlyList<ServerEndpoint> endpoints,
        ServerCapabilityName capability,
        string httpMethod,
        bool startsNewFlow)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);

        foreach(ServerEndpoint endpoint in endpoints)
        {
            if(endpoint.Capability == capability
                && string.Equals(endpoint.HttpMethod, httpMethod, StringComparison.OrdinalIgnoreCase)
                && endpoint.StartsNewFlow == startsNewFlow)
            {
                return endpoint;
            }
        }

        return null;
    }


    /// <summary>
    /// Finds the first endpoint matching the given capability and HTTP method,
    /// additionally filtering by a request fields predicate when the endpoint
    /// has <see cref="ServerEndpoint.MatchesRequest"/> set.
    /// </summary>
    /// <param name="endpoints">The endpoint list from <see cref="AuthorizationServer.GetEndpoints"/>.</param>
    /// <param name="capability">The capability to match.</param>
    /// <param name="httpMethod">The HTTP method to match.</param>
    /// <param name="fields">
    /// The request fields to test against <see cref="ServerEndpoint.MatchesRequest"/>.
    /// </param>
    /// <returns>
    /// The matching endpoint, or <see langword="null"/> if no endpoint matches.
    /// </returns>
    public static ServerEndpoint? Find(
        IReadOnlyList<ServerEndpoint> endpoints,
        ServerCapabilityName capability,
        string httpMethod,
        RequestFields fields)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpMethod);
        ArgumentNullException.ThrowIfNull(fields);

        foreach(ServerEndpoint endpoint in endpoints)
        {
            if(endpoint.Capability != capability)
            {
                continue;
            }

            if(!string.Equals(endpoint.HttpMethod, httpMethod, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if(endpoint.MatchesRequest is not null && !endpoint.MatchesRequest(fields))
            {
                continue;
            }

            return endpoint;
        }

        return null;
    }
}
