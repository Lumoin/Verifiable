using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm.Routing;

/// <summary>
/// The well-known names of the DIDComm Messaging service endpoint — the <c>DIDCommMessaging</c> service
/// type and the <c>serviceEndpoint</c> object member names — per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#service-endpoint">DIDComm Messaging v2.1 §Service Endpoint</see>.
/// </summary>
/// <remarks>
/// Each name declares its single UTF-8 source literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property and derives the
/// interned string view through <see cref="Utf8Constants.ToInternedString"/>, matching
/// <see cref="WellKnownRoutingNames"/> and <see cref="WellKnownDidCommMemberNames"/>. The member names are the keys of
/// a <c>serviceEndpoint</c> object as carried in <see cref="Verifiable.Core.Model.Did.Service.ServiceEndpointMap"/> /
/// <see cref="Verifiable.Core.Model.Did.Service.ServiceEndpoints"/>; the <c>didcomm/v2</c> profile a service's
/// <c>accept</c> array lists is <see cref="WellKnownRoutingNames.Profile"/>.
/// </remarks>
public static class WellKnownDidCommServiceNames
{
    /// <summary>The UTF-8 source literal of <see cref="DidCommMessagingServiceType"/>.</summary>
    public static ReadOnlySpan<byte> DidCommMessagingServiceTypeUtf8 => "DIDCommMessaging"u8;

    /// <summary>
    /// The DIDComm Messaging service type — the value of a service's <c>type</c> that identifies it as a DIDComm
    /// Messaging endpoint (DIDComm v2.1 §Service Endpoint: "type - REQUIRED. MUST be DIDCommMessaging").
    /// </summary>
    public static readonly string DidCommMessagingServiceType = Utf8Constants.ToInternedString(DidCommMessagingServiceTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Uri"/>.</summary>
    public static ReadOnlySpan<byte> UriUtf8 => "uri"u8;

    /// <summary>The <c>serviceEndpoint.uri</c> member — REQUIRED. A transport URI, or a mediator DID (DIDComm v2.1 §Service Endpoint).</summary>
    public static readonly string Uri = Utf8Constants.ToInternedString(UriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Accept"/>.</summary>
    public static ReadOnlySpan<byte> AcceptUtf8 => "accept"u8;

    /// <summary>The <c>serviceEndpoint.accept</c> member — OPTIONAL. The media-type/profile preferences of the endpoint (DIDComm v2.1 §Service Endpoint).</summary>
    public static readonly string Accept = Utf8Constants.ToInternedString(AcceptUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RoutingKeys"/>.</summary>
    public static ReadOnlySpan<byte> RoutingKeysUtf8 => "routingKeys"u8;

    /// <summary>The <c>serviceEndpoint.routingKeys</c> member — OPTIONAL. The ordered key refs for the forward wrap (DIDComm v2.1 §Service Endpoint).</summary>
    public static readonly string RoutingKeys = Utf8Constants.ToInternedString(RoutingKeysUtf8);
}
