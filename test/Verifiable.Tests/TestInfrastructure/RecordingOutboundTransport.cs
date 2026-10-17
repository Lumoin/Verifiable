using Verifiable.Core.Outbound;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Wraps a real <see cref="OutboundTransportDelegate"/> to record, in call order and without sending a request of its
/// own, either each response's <c>Content-Type</c> field (<see cref="Wrap"/>) or each request the guarded fetch
/// (<see cref="OutboundFetch"/>) handed to the transport (<see cref="WrapRequests"/>): the seams a real-wire test uses
/// to assert what actually crossed the socket alongside the requests the guarded fetch made, rather than hand-rolling a
/// parallel HTTP call just to inspect them.
/// </summary>
internal static class RecordingOutboundTransport
{
    /// <summary>
    /// Wraps <paramref name="transport"/>, recording every response's <c>Content-Type</c> field value
    /// (or <see langword="null"/> when the field is absent) in the order responses arrive.
    /// </summary>
    /// <param name="transport">The transport to wrap.</param>
    /// <returns>The wrapped transport, and an accessor for the content types recorded so far.</returns>
    public static (OutboundTransportDelegate Transport, Func<IReadOnlyList<string?>> ContentTypes) Wrap(
        OutboundTransportDelegate transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        List<string?> contentTypes = [];

        //Forwards the reader unchanged and records the completed response content type.
        async ValueTask<OutboundTransportResult> recording(OutboundRequest request, Verifiable.Core.ExchangeContext context, OutboundResponseReaderDelegate readResponse, CancellationToken cancellationToken)
        {
            OutboundTransportResult response = await transport(request, context, readResponse, cancellationToken).ConfigureAwait(false);
            string? contentType = response.Response?.Headers.ContentType;
            contentTypes.Add(contentType);

            return response;
        }

        return (recording, () => contentTypes);
    }


    /// <summary>
    /// Wraps <paramref name="transport"/>, recording every request handed to it, in call order, before forwarding it
    /// unchanged: the seam a real-wire test reads to assert which requests the guarded fetch sent, and that it sent none
    /// where it must not dial.
    /// </summary>
    /// <param name="transport">The transport to wrap.</param>
    /// <returns>The wrapped transport, and an accessor for the requests recorded so far.</returns>
    public static (OutboundTransportDelegate Transport, Func<IReadOnlyList<OutboundRequest>> Requests) WrapRequests(
        OutboundTransportDelegate transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        List<OutboundRequest> requests = [];

        //Records the request as handed over, then forwards it and its reader unchanged.
        ValueTask<OutboundTransportResult> recording(OutboundRequest request, Verifiable.Core.ExchangeContext context, OutboundResponseReaderDelegate readResponse, CancellationToken cancellationToken)
        {
            lock(requests)
            {
                requests.Add(request);
            }

            return transport(request, context, readResponse, cancellationToken);
        }

        //Copies the requests recorded so far.
        IReadOnlyList<OutboundRequest> recorded()
        {
            lock(requests)
            {
                return [.. requests];
            }
        }

        return (recording, recorded);
    }
}
