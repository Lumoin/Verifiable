using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core.OutboundFetch;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Wraps a real <see cref="OutboundTransportDelegate"/> to record each response's <c>Content-Type</c> field,
/// in call order, without sending a request of its own — the seam a real-wire test uses to assert what
/// actually crossed the socket alongside the request the guarded fetch (<see cref="OutboundFetch"/>) already
/// made, rather than hand-rolling a parallel HTTP call just to inspect the response.
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

        OutboundTransportDelegate recording = async (request, context, cancellationToken) =>
        {
            OutboundResponse response = await transport(request, context, cancellationToken).ConfigureAwait(false);
            response.Headers.TryGetValue(WellKnownHttpHeaderNames.ContentType, out string? contentType);
            contentTypes.Add(contentType);

            return response;
        };

        return (recording, () => contentTypes);
    }
}
