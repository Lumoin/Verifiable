using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Foundation;

namespace Verifiable.DidComm.Transport;

/// <summary>
/// The DIDComm Messaging HTTPS binding — adapts an application's single-hop HTTP transport into a transport-neutral
/// <see cref="DidCommSendDelegate"/> that delivers a packed DIDComm message as an HTTPS POST, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#https">DIDComm Messaging v2.1 §Transports §HTTPS</see>.
/// Every channel — HTTPS here, WebSocket/Bluetooth/libp2p elsewhere — flows through the one neutral transmit surface
/// (<see cref="DidCommTransportExtensions"/>); HTTP is just one <see cref="DidCommSendDelegate"/>, not privileged.
/// </summary>
/// <remarks>
/// <para>
/// DIDComm is transport-independent — the envelope, not the connection, provides trust — so this library carries no
/// <c>System.Net</c>: the actual send is the application's injected <see cref="OutboundTransportDelegate"/>, routed
/// through the SSRF-policed <see cref="OutboundFetch"/> (the delivery endpoint comes from a recipient's untrusted DID
/// document, so the secure default's HTTPS-only, loopback/private-blocking policy applies). This type only encodes the
/// §HTTPS conventions onto the request: the message is sent via <c>POST</c> (L1118), its IANA media type is set as the
/// <c>Content-Type</c> (L1120), and a 2xx response is a successful receipt (L1122, 202 Accepted recommended). The POST
/// is one-way: no application response flows back in the HTTP response (L1124).
/// </para>
/// <para>
/// Redirect handling is the <see cref="OutboundFetchPolicy"/>'s, not this type's. Under the secure default no redirect
/// is followed, so a relocation surfaces as a <see cref="DidCommTransmitError.TransportFailed"/> and the sender
/// re-resolves the recipient's DID document — the relocation discipline §HTTPS prescribes ("permanent endpoint
/// relocation should be managed with a DID Document update"). A caller that relaxes the policy to follow redirects owns
/// the §HTTPS constraint that only a temporary <c>307</c> is acceptable (a body-dropping <c>301</c>/<c>302</c>/<c>303</c>
/// rewrite would silently fail to deliver the one-way POST).
/// </para>
/// <para>
/// The transmit is fail-soft over the network: a policy denial, a transport error, or a non-2xx status are returned as
/// a typed <see cref="DidCommTransmitResult"/> rather than thrown, so a sender can fail over to another endpoint or
/// retry later (DIDComm v2.1 §Failover). Producer-side null guards on the caller arguments MAY throw.
/// </para>
/// </remarks>
public static class DidCommHttpTransport
{
    //The HTTP header that carries the message's IANA media type (DIDComm v2.1 §HTTPS L1120).
    private const string ContentTypeHeader = "Content-Type";

    //A one-way DIDComm POST expects only a small status receipt; the response body is never read (§HTTPS L1124),
    //so a tight cap lets a cooperating transport abort an oversized reply rather than buffering it (the M3
    //response-size bound, extended to the transmit path).
    private static long MaxAcceptResponseBytes => 8 * 1024;


    /// <summary>
    /// Adapts a single-hop HTTP transport into a transport-neutral <see cref="DidCommSendDelegate"/> that POSTs a
    /// message with its media type as <c>Content-Type</c> through the SSRF-policed <see cref="OutboundFetch"/>
    /// (DIDComm v2.1 §HTTPS). This is how the HTTPS binding is used polymorphically alongside other channels: a
    /// caller selects a send delegate by the endpoint's scheme and routes every channel through the one neutral
    /// <see cref="DidCommTransportExtensions"/> transmit surface.
    /// </summary>
    /// <param name="transport">The application's single-hop HTTP transport.</param>
    /// <returns>A send delegate that delivers a DIDComm message over HTTPS.</returns>
    public static DidCommSendDelegate CreateSendDelegate(OutboundTransportDelegate transport)
    {
        ArgumentNullException.ThrowIfNull(transport);

        return (message, mediaType, endpoint, context, cancellationToken) =>
            TransmitCoreAsync(message, mediaType, endpoint, context, transport, cancellationToken);
    }


    //Builds the HTTPS POST request (Content-Type = the message media type, body = the message bytes), sends it through
    //the SSRF-policed OutboundFetch, and maps the outcome to a typed result. The body wraps the message's memory as a
    //BORROWED view (no copy), valid only for the duration of this call — the message is alive throughout, and the
    //transport consumes the request synchronously within the await, so the transport MUST NOT retain the body past its
    //returned task. The HTTP response body is not read — DIDComm POST is one-way (DIDComm v2.1 §HTTPS L1124).
    private static async ValueTask<DidCommTransmitResult> TransmitCoreAsync(
        ReadOnlyMemory<byte> body,
        string mediaType,
        Uri endpoint,
        ExchangeContext context,
        OutboundTransportDelegate transport,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(transport);

        var request = new OutboundRequest
        {
            Target = endpoint,
            Method = "POST",
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { [ContentTypeHeader] = mediaType },
            Body = new TaggedMemory<byte>(body, Tag.Empty),
            MaxResponseBytes = MaxAcceptResponseBytes
        };

        OutboundFetchResult fetch;
        try
        {
            fetch = await OutboundFetch.FetchAsync(request, context, transport, cancellationToken).ConfigureAwait(false);
        }
        catch(OperationCanceledException)
        {
            throw;
        }
        catch
        {
            //A transport-level failure (socket/DNS/connection) is fail-soft: the sender may fail over or retry.
            return DidCommTransmitResult.TransportFailed();
        }

        if(fetch.Outcome == OutboundFetchOutcome.DeniedByPolicy)
        {
            return DidCommTransmitResult.DeniedByPolicy();
        }

        //A non-fetched outcome that was not a policy denial — a redirect not followed or too many redirects — is
        //folded into a transport failure: under the secure default no redirects are followed (RedirectMode.None), so
        //a relocation surfaces here and the sender re-resolves the recipient's DID document, the relocation discipline
        //§HTTPS prescribes ("permanent endpoint relocation should be managed with a DID Document update").
        if(!fetch.IsFetched || fetch.Response is not { } response)
        {
            return DidCommTransmitResult.TransportFailed();
        }

        //A successful receipt MUST return a 2xx status (DIDComm v2.1 §HTTPS L1122); FromStatus maps the range.
        return DidCommTransmitResult.FromStatus(response.StatusCode);
    }
}
