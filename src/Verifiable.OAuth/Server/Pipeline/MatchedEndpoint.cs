using System.Diagnostics;

using Verifiable.OAuth.Server.Routing;
namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// The result of a successful match against an <see cref="EndpointChain"/>:
/// the matched <see cref="ServerEndpoint"/> paired with the typed
/// <see cref="MatchPayload"/> that the endpoint's
/// <see cref="MatchRequestDelegate"/> produced (or
/// <see cref="MatchPayload.Empty"/> when the endpoint had no
/// <see cref="ServerEndpoint.MatchesRequest"/> delegate).
/// </summary>
/// <remarks>
/// <para>
/// The dispatcher receives a <see cref="MatchedEndpoint"/> from
/// <see cref="EndpointChain.MatchAsync"/>, places its
/// <see cref="Payload"/> on the request context via
/// <see cref="RequestContextExtensions.SetMatchPayload"/>, and then invokes
/// the endpoint's handlers. Handlers that consume the payload read it back
/// through <see cref="RequestContextExtensions.MatchPayload"/> and pattern-match
/// to the subtype they expect.
/// </para>
/// </remarks>
/// <param name="Endpoint">The matched <see cref="ServerEndpoint"/>.</param>
/// <param name="Payload">
/// The typed classification produced by the endpoint's matcher, or
/// <see cref="MatchPayload.Empty"/> when the endpoint had no
/// <see cref="ServerEndpoint.MatchesRequest"/> delegate.
/// </param>
[DebuggerDisplay("MatchedEndpoint {Endpoint.HttpMethod,nq} Capability={Endpoint.Capability} Payload={Payload}")]
public sealed record MatchedEndpoint(ServerEndpoint Endpoint, MatchPayload Payload);
