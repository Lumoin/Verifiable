using System.Threading;
using System.Threading.Tasks;

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
/// This is the only HTTP-bearing piece, and it lives with the application/test
/// transport — <see cref="Verifiable.Core"/> takes no <c>System.Net.Http</c>
/// dependency. A reference DNS-pinning implementation (the connection-time guard
/// against rebinding) is provided in the transport layer, not here.
/// </remarks>
/// <param name="request">The single request to perform.</param>
/// <param name="context">The per-call exchange context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The single-hop response (a 3xx is returned, not followed).</returns>
public delegate ValueTask<OutboundResponse> OutboundTransportDelegate(
    OutboundRequest request,
    ExchangeContext context,
    CancellationToken cancellationToken);
