using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Issues a JSON PUT request to <paramref name="endpoint"/> with the given
/// body and composed headers, and returns the server's response. Used by
/// RFC 7592 §2.2 update-client-metadata calls.
/// </summary>
/// <remarks>
/// The transport implementation sets <c>Content-Type</c> to
/// <c>application/json</c> and attaches every entry in
/// <see cref="OutgoingHeaders.Values"/> to the outbound request. The
/// library composes the <c>Authorization</c> header before calling.
/// </remarks>
/// <param name="endpoint">The URI to PUT to.</param>
/// <param name="jsonBody">The serialised JSON body.</param>
/// <param name="headers">Composed request headers.</param>
/// <param name="context">The threaded per-operation <see cref="ExchangeContext"/> for per-tenant transport selection.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<HttpResponseData> SendJsonPutDelegate(
    Uri endpoint,
    string jsonBody,
    OutgoingHeaders headers,
    ExchangeContext context,
    CancellationToken cancellationToken);
