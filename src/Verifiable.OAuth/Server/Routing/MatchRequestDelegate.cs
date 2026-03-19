namespace Verifiable.OAuth.Server.Routing;

/// <summary>
/// The required per-endpoint matcher that decides whether an inbound request
/// is accepted by the endpoint, returning a typed <see cref="MatchPayload"/>
/// when it is or <see langword="null"/> when it is not.
/// </summary>
/// <remarks>
/// <para>
/// Every <see cref="ServerEndpoint"/> declares one. The matcher's body is the
/// endpoint's complete acceptance test: every signal it consults — path
/// suffix, HTTP method, body fields, headers, route values, registration
/// capability, context state — is visible in the matcher's source.
/// <see cref="EndpointChain.MatchAsync"/> walks the chain in order and
/// invokes each matcher with no upstream filtering on
/// <see cref="ServerEndpoint.HttpMethod"/> or
/// <see cref="ServerEndpoint.Capability"/>; those fields are descriptive
/// metadata for telemetry and discovery, not routing inputs. The first
/// matcher to return a non-<see langword="null"/>
/// <see cref="MatchPayload"/> wins.
/// </para>
/// <para>
/// Matchers that accept a request without carrying classification data into
/// the handler return <see cref="MatchPayload.Empty"/>. Matchers that
/// classify the request — extracting a token shape, parsing a JWS header,
/// pulling out a typed payload — return their endpoint-specific
/// <see cref="MatchPayload"/> subtype, which the dispatcher places on the
/// <see cref="RequestContext"/> for the handler to read.
/// </para>
/// <para>
/// <strong>Cheap signals first.</strong>
/// A matcher that does expensive work — async storage lookups, cryptographic
/// parsing, network round-trips — should fail-fast on cheap signals before
/// committing to that work. Hostile inbound requests that touch many
/// matchers should not be able to force every matcher's expensive path to
/// run.
/// </para>
/// <para>
/// <strong>Disjointness.</strong>
/// Matchers within a chain must be mutually disjoint: at most one endpoint
/// in the chain should return a non-<see langword="null"/> payload for any
/// given inbound request. The chain walker stops at the first non-<see langword="null"/>
/// match; overlap between matchers makes endpoint selection
/// order-dependent and can be exploited to route a request to a
/// more-permissive handler than intended. The library asserts disjointness
/// in debug builds; production builds rely on the application author to
/// honor the invariant.
/// </para>
/// <para>
/// <strong>Cancellation.</strong>
/// Implementations must honor <paramref name="cancellationToken"/>. A
/// matcher that ignores cancellation gives hostile inbound requests an
/// avenue for resource exhaustion.
/// </para>
/// <para>
/// <strong>State capture.</strong>
/// Implementations should be static method groups or static lambdas with
/// no lexical closure over mutable state. State the matcher needs flows
/// through <paramref name="fields"/> or <paramref name="context"/>, not
/// through captured variables.
/// </para>
/// </remarks>
/// <param name="fields">
/// The parsed request fields from the HTTP form body, query string, or both.
/// </param>
/// <param name="context">
/// The per-request context populated by the application skin and enriched
/// by the dispatcher.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// A non-<see langword="null"/> <see cref="MatchPayload"/> when the endpoint
/// matches the request, or <see langword="null"/> when it does not. Use
/// <see cref="MatchPayload.Empty"/> when the endpoint matches but has no
/// classification data to carry.
/// </returns>
public delegate ValueTask<MatchPayload?> MatchRequestDelegate(
    RequestFields fields,
    RequestContext context,
    CancellationToken cancellationToken);
