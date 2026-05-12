namespace Verifiable.OAuth.Client;

/// <summary>
/// Issues a JSON DELETE request to <paramref name="endpoint"/> with the
/// composed headers, and returns the server's response. Used by RFC 7592
/// §2.3 deregister-client calls.
/// </summary>
/// <remarks>
/// The transport implementation attaches every entry in
/// <see cref="OutgoingHeaders.Values"/> to the outbound request. The
/// library composes the <c>Authorization</c> header before calling.
/// RFC 7592 §2.3 expects a 204 No Content response; the response body is
/// typically empty.
/// </remarks>
/// <param name="endpoint">The URI to DELETE.</param>
/// <param name="headers">Composed request headers.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<HttpResponseData> SendJsonDeleteDelegate(
    Uri endpoint,
    OutgoingHeaders headers,
    CancellationToken cancellationToken);
