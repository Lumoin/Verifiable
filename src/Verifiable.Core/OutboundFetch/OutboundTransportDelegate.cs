namespace Verifiable.Core.OutboundFetch;

/// <summary>
/// A <strong>single-hop</strong> HTTP transport — the application-supplied
/// network primitive the guarded <see cref="OutboundFetch"/> drives. It performs
/// exactly one request/response and <strong>must not follow redirects</strong>
/// (configure the underlying handler with auto-redirect disabled): the guarded
/// fetch owns the redirect loop so each hop is re-validated against the
/// <see cref="OutboundFetchPolicy"/>.
/// </summary>
/// <remarks>
/// <para>
/// This is the only HTTP-bearing piece, and it lives with the application/test
/// transport — <see cref="Verifiable.Core"/> takes no <c>System.Net.Http</c>
/// dependency. A reference DNS-pinning implementation (the connection-time guard
/// against rebinding) is provided in the transport layer, not here.
/// </para>
/// <para>
/// <see cref="OutboundRequest.Target"/> is drawn from resolved or otherwise semi-trusted data —
/// federation/OAuth metadata, a DID document's service endpoints, a JSON-LD <c>@context</c> URL —
/// and may share an origin with the application's own backend. A browser host therefore sends
/// every request this implementation builds with credentials omitted
/// (<c>BrowserRequestCredentials.Omit</c> on the request, in the application's own transport),
/// because the Fetch Standard's default credentials mode is <c>same-origin</c>: "A request has an
/// associated credentials mode, which is 'omit', 'same-origin', or 'include'. Unless stated
/// otherwise, it is 'same-origin'." This delegate places no origin restriction on the target;
/// <see cref="OutboundFetch"/> evaluates only <see cref="OutboundFetchPolicy"/>.
/// </para>
/// </remarks>
/// <param name="request">The single request to perform.</param>
/// <param name="context">The per-call exchange context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The single-hop response (a 3xx is returned, not followed).</returns>
public delegate ValueTask<OutboundResponse> OutboundTransportDelegate(
    OutboundRequest request,
    ExchangeContext context,
    CancellationToken cancellationToken);
