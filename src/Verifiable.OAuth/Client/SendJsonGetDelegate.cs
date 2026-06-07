using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Issues a JSON GET request to <paramref name="endpoint"/> with the
/// composed <paramref name="headers"/> and returns the server's response.
/// Used by RFC 7592 §2.1 read-client-metadata calls.
/// </summary>
/// <remarks>
/// The transport implementation attaches every entry in
/// <see cref="OutgoingHeaders.Values"/> to the outbound request and sets
/// <c>Accept</c> to <c>application/json</c>. The library composes the
/// <c>Authorization</c> header (typically <c>Bearer</c> with the
/// registration access token) before calling this delegate; the transport
/// stays auth-scheme-naive.
/// </remarks>
/// <param name="endpoint">The URI to GET from.</param>
/// <param name="headers">Composed request headers.</param>
/// <param name="context">The threaded per-operation <see cref="ExchangeContext"/> for per-tenant transport selection.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The HTTP response carrying body, status code, and response headers.</returns>
public delegate ValueTask<HttpResponseData> SendJsonGetDelegate(
    Uri endpoint,
    OutgoingHeaders headers,
    ExchangeContext context,
    CancellationToken cancellationToken);
