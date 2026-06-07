using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

using Verifiable.Core;
using Verifiable.OAuth.Server.Routing;
namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// An immutable, ordered chain of <see cref="ServerEndpoint"/> records that
/// the dispatcher walks to select the endpoint matching an inbound request.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="EndpointChain"/> is the runtime form of an
/// <see cref="EndpointBuilderSet"/> applied to a specific
/// <see cref="ClientRecord"/> in the context of an inbound request:
/// the set's builder modules each contribute the endpoints their flow
/// supports for that registration and request, and the contributed
/// endpoints are concatenated in the order their producing builders
/// contribute them. The chain itself is constructed by
/// <see cref="BuildForRequest"/>.
/// </para>
/// <para>
/// <strong>Walking the chain.</strong>
/// <see cref="MatchAsync"/> walks the endpoints in order, invoking each
/// endpoint's <see cref="ServerEndpoint.MatchesRequest"/> predicate. The
/// first endpoint whose <see cref="MatchRequestDelegate"/> returns a
/// non-<see langword="null"/> <see cref="MatchPayload"/> wins. The chain
/// runner does not pre-filter on
/// <see cref="ServerEndpoint.Capability"/> or
/// <see cref="ServerEndpoint.HttpMethod"/>; capability is descriptive
/// metadata read post-match for telemetry and discovery, and HTTP method
/// is part of each matcher's own acceptance test. Each
/// <see cref="MatchRequestDelegate"/> body is the complete acceptance
/// test: every signal a matcher consults — path, method, body fields,
/// headers, route values, registration capability, context state — is
/// visible in the matcher's source.
/// </para>
/// <para>
/// Matchers that match unconditionally on no signals beyond an inert
/// presence return <see cref="MatchPayload.Empty"/>; matchers that carry
/// pre-decoded data into the handler return a typed
/// <see cref="MatchPayload"/> subtype.
/// </para>
/// <para>
/// <strong>Disjointness.</strong>
/// Endpoints within a chain must be mutually disjoint with respect to a
/// given inbound request: at most one should match. Overlap makes selection
/// order-dependent and can be exploited to route a request to a
/// more-permissive handler than intended. The library asserts disjointness
/// in debug builds (<see cref="Debug.Assert(bool)"/> walks the entire chain
/// and asserts at most one match); release builds rely on the application
/// author to honor the invariant.
/// </para>
/// <para>
/// <strong>Concurrency.</strong>
/// The chain is fully immutable. A single instance is safe for concurrent
/// reads. Configuration changes flow through
/// <see cref="AuthorizationServer.ApplyConfiguration"/>, which atomically
/// publishes a new <see cref="ServerConfiguration"/>; subsequent calls to
/// <see cref="BuildForRequest"/> derive new chains from the new
/// configuration's <see cref="ServerConfiguration.EndpointBuilders"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("EndpointChain Count={Count}")]
public sealed class EndpointChain: IReadOnlyList<ServerEndpoint>
{
    private ServerEndpoint[] Endpoints { get; }


    /// <summary>
    /// An empty <see cref="EndpointChain"/>.
    /// </summary>
    public static EndpointChain Empty { get; } = new(Array.Empty<ServerEndpoint>());


    /// <summary>
    /// Constructs a chain from a list of endpoints. The chain takes a
    /// snapshot; subsequent mutations of the source list have no effect.
    /// </summary>
    /// <param name="endpoints">
    /// The endpoints in the order the chain should walk them.
    /// </param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="endpoints"/> is <see langword="null"/>.
    /// </exception>
    public EndpointChain(IEnumerable<ServerEndpoint> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        Endpoints = endpoints.ToArray();
    }


    private EndpointChain(ServerEndpoint[] endpoints)
    {
        Endpoints = endpoints;
    }


    /// <summary>
    /// Builds the chain of active endpoints for a registration and inbound
    /// request. Calls
    /// <see cref="AuthorizationServerIntegration.ResolveCapabilitiesAsync"/>
    /// once to obtain the per-call active capability set, then invokes each
    /// <see cref="EndpointBuilderDelegate"/> on
    /// <see cref="ServerConfiguration.EndpointBuilders"/>, filters the
    /// produced <see cref="EndpointCandidate"/> instances by capability
    /// membership, and asks
    /// <see cref="AuthorizationServerIntegration.ResolveEndpointUriAsync"/>
    /// for each survivor's absolute URL. Candidates with no resolvable URL
    /// are dropped silently. Surviving candidates are projected to
    /// <see cref="ServerEndpoint"/> records with the resolved URI attached.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The chain is fresh per request — the same registration may produce
    /// different chains in different requests when a builder gates on
    /// context or when <c>ResolveCapabilitiesAsync</c> attenuates
    /// capabilities based on CAEP/RISC signals or other per-request state.
    /// </para>
    /// <para>
    /// <see cref="ExchangeContextServerExtensions.Server"/> on
    /// <paramref name="context"/> must be set before this call; the
    /// dispatcher places it on the context at
    /// <see cref="AuthorizationServer.DispatchAsync"/> entry. Callers
    /// driving the chain outside the dispatcher must call
    /// <see cref="ExchangeContextServerExtensions.SetServer"/> themselves.
    /// </para>
    /// </remarks>
    /// <param name="registration">
    /// The client registration whose capabilities determine which endpoints
    /// each module produces.
    /// </param>
    /// <param name="context">
    /// The per-request context, carrying the active
    /// <see cref="AuthorizationServer"/> via
    /// <see cref="ExchangeContextServerExtensions.Server"/>, the typed
    /// <see cref="IncomingRequest"/> envelope, resolved
    /// <see cref="ClientRecord"/>, and any application-supplied
    /// request-scoped state.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The chain of endpoints for this registration and request. May be empty
    /// when no modules produce candidates or when capability filtering /
    /// URL resolution eliminate every candidate.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="registration"/> or
    /// <paramref name="context"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <see cref="ExchangeContextServerExtensions.Server"/> on
    /// <paramref name="context"/> is <see langword="null"/>.
    /// </exception>
    public static async ValueTask<EndpointChain> BuildForRequestAsync(
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        AuthorizationServer server = context.Server
            ?? throw new InvalidOperationException(
                "context.Server must be set before BuildForRequestAsync. "
                + "DispatchAsync sets this at entry; callers that drive the "
                + "chain outside the dispatcher must call context.SetServer "
                + "before invoking this method.");

        EndpointBuilderSet builders = server.Configuration.EndpointBuilders;
        if(builders.Count == 0) { return Empty; }

        //Per-call capability set — CAEP/RISC attenuation point. The library
        //default returns registration.AllowedCapabilities unchanged; custom
        //wirings narrow the set in response to per-request signals.
        IReadOnlySet<CapabilityIdentifier> allowedCapabilities =
            await server.Integration.ResolveCapabilitiesAsync!(
                registration, context, cancellationToken).ConfigureAwait(false);

        //Stash on the context so request-time gating sites running inside
        //handlers (e.g., token-producer attenuation) can read the same
        //resolver output without re-invoking the delegate.
        context.SetResolvedCapabilities(allowedCapabilities);

        List<ServerEndpoint> resolved = [];
        foreach(EndpointBuilderDelegate builder in builders)
        {
            IReadOnlyList<EndpointCandidate> candidates = await builder(
                registration, context, cancellationToken).ConfigureAwait(false);

            foreach(EndpointCandidate candidate in candidates)
            {
                if(!allowedCapabilities.Contains(candidate.Capability)) { continue; }

                Uri? uri = await server.Integration.ResolveEndpointUriAsync!(
                    candidate.Name, registration, context, cancellationToken)
                    .ConfigureAwait(false);

                if(uri is null) { continue; }

                resolved.Add(new ServerEndpoint
                {
                    Name = candidate.Name,
                    Capability = candidate.Capability,
                    HttpMethod = candidate.HttpMethod,
                    Kind = candidate.Kind,
                    StartsNewFlow = candidate.StartsNewFlow,
                    MatchesRequest = candidate.MatchesRequest,
                    BuildInputAsync = candidate.BuildInputAsync,
                    BuildResponse = candidate.BuildResponse,
                    ExtractCorrelationKey = candidate.ExtractCorrelationKey,
                    DiscoveryMetadataKey = candidate.DiscoveryMetadataKey,
                    ResolvedUri = uri
                });
            }
        }

        return new EndpointChain(resolved.ToArray());
    }


    /// <summary>
    /// The number of endpoints in the chain.
    /// </summary>
    public int Count => Endpoints.Length;

    /// <summary>
    /// The endpoint at the given position.
    /// </summary>
    public ServerEndpoint this[int index] => Endpoints[index];


    /// <summary>
    /// Walks the chain in order, returning the first endpoint whose
    /// <see cref="ServerEndpoint.MatchesRequest"/> accepts the inbound
    /// request, paired with the typed payload the matcher produced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The chain walk does not pre-filter on
    /// <see cref="ServerEndpoint.Capability"/> or
    /// <see cref="ServerEndpoint.HttpMethod"/>. Every endpoint's matcher
    /// runs in registration order; each matcher's body declares its full
    /// acceptance test, including any path, method, body-field, or
    /// capability checks. The first matcher to return non-<see langword="null"/>
    /// wins.
    /// </para>
    /// <para>
    /// In DEBUG builds the walk continues past the first match to assert
    /// that at most one endpoint accepted the request. Disjointness across
    /// matchers in a chain is the authoring discipline the assertion
    /// enforces.
    /// </para>
    /// </remarks>
    /// <param name="fields">The parsed request fields.</param>
    /// <param name="context">
    /// The per-request context. The dispatcher places the typed
    /// <see cref="IncomingRequest"/> on it before this walk; matchers read
    /// path, method, headers, and route values from there.
    /// </param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The matched endpoint and its produced payload, or
    /// <see langword="null"/> when no endpoint in the chain matches.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="fields"/> or <paramref name="context"/>
    /// is <see langword="null"/>.
    /// </exception>
    public async ValueTask<MatchedEndpoint?> MatchAsync(
        RequestFields fields,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fields);
        ArgumentNullException.ThrowIfNull(context);

        cancellationToken.ThrowIfCancellationRequested();

#if DEBUG
        MatchedEndpoint? firstMatch = null;
        int matchCount = 0;

        for(int i = 0; i < Endpoints.Length; i++)
        {
            ServerEndpoint endpoint = Endpoints[i];

            MatchPayload? payload = await endpoint.MatchesRequest(fields, context, endpoint, cancellationToken)
                .ConfigureAwait(false);
            if(payload is null)
            {
                continue;
            }

            //In debug builds the loop continues past the first match so the
            //assertion below can verify at most one endpoint matched; in
            //release builds the loop short-circuits at the first match and
            //the assertion is compiled out.
            if(firstMatch is null)
            {
                firstMatch = new MatchedEndpoint(endpoint, payload);
            }

            matchCount++;
        }

        Debug.Assert(matchCount <= 1,
            $"EndpointChain disjointness violated: {matchCount} endpoints matched the same request. "
            + "Matchers within a chain must be mutually disjoint; review the order and conditions of "
            + "the chain's MatchesRequest delegates.");

        return firstMatch;
#else
        for(int i = 0; i < Endpoints.Length; i++)
        {
            ServerEndpoint endpoint = Endpoints[i];

            MatchPayload? payload = await endpoint.MatchesRequest(fields, context, endpoint, cancellationToken)
                .ConfigureAwait(false);
            if(payload is null)
            {
                continue;
            }

            return new MatchedEndpoint(endpoint, payload);
        }

        return null;
#endif
    }


    /// <summary>
    /// Returns a new chain with <paramref name="endpoint"/> appended after
    /// the existing endpoints.
    /// </summary>
    /// <param name="endpoint">The endpoint to append.</param>
    /// <returns>A new <see cref="EndpointChain"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="endpoint"/> is <see langword="null"/>.
    /// </exception>
    public EndpointChain Add(ServerEndpoint endpoint)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ServerEndpoint[] next = new ServerEndpoint[Endpoints.Length + 1];
        for(int i = 0; i < Endpoints.Length; i++)
        {
            next[i] = Endpoints[i];
        }
        next[Endpoints.Length] = endpoint;
        return new EndpointChain(next);
    }


    /// <summary>
    /// Returns a new chain combining this chain with another, preserving the
    /// order of <paramref name="other"/>'s endpoints after this chain's.
    /// </summary>
    /// <param name="other">The chain to append.</param>
    /// <returns>A new <see cref="EndpointChain"/> instance.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="other"/> is <see langword="null"/>.
    /// </exception>
    public EndpointChain Plus(EndpointChain other)
    {
        ArgumentNullException.ThrowIfNull(other);
        if(other.Endpoints.Length == 0)
        {
            return this;
        }
        if(Endpoints.Length == 0)
        {
            return other;
        }

        ServerEndpoint[] next = new ServerEndpoint[Endpoints.Length + other.Endpoints.Length];
        for(int i = 0; i < Endpoints.Length; i++)
        {
            next[i] = Endpoints[i];
        }
        for(int j = 0; j < other.Endpoints.Length; j++)
        {
            next[Endpoints.Length + j] = other.Endpoints[j];
        }

        return new EndpointChain(next);
    }


    /// <inheritdoc/>
    public IEnumerator<ServerEndpoint> GetEnumerator() => ((IEnumerable<ServerEndpoint>)Endpoints).GetEnumerator();

    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => Endpoints.GetEnumerator();
}
