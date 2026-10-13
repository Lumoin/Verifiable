using Verifiable.Core.Transport;

namespace Verifiable.Core.Outbound;

/// <summary>
/// Reads one response on behalf of the guarded fetch. The transport supplies the headers and the
/// live body stream, awaits this delegate exactly once, and returns its result unchanged. It keeps
/// the response and stream alive until this delegate returns, then disposes them even on failure.
/// </summary>
/// <remarks>
/// The reader owns the size decision. A declared length over the limit returns without reading;
/// otherwise it reads at most the limit plus one byte before returning a typed refusal. The transport
/// must neither buffer the response first nor apply a separate size limit. Connection, decoding, and
/// read failures remain exceptions; cancellation propagates. Automatic redirects must be disabled.
/// </remarks>
/// <param name="statusCode">The received HTTP status.</param>
/// <param name="headers">The received response headers.</param>
/// <param name="body">The readable body as it arrives; ownership remains with the transport.</param>
/// <param name="cancellationToken">The cancellation token carried by the transport call.</param>
/// <returns>The completed response or the size refusal that caused reading to stop early.</returns>
public delegate ValueTask<OutboundTransportResult> OutboundResponseReaderDelegate(
    int statusCode,
    HttpHeaderSet headers,
    Stream body,
    CancellationToken cancellationToken);
