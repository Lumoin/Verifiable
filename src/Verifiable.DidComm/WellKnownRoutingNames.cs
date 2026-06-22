using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm;

/// <summary>
/// The well-known names of the DIDComm Routing Protocol 2.0 — the <c>forward</c> message Type URI, the
/// <c>next</c> body member, and the <c>didcomm/v2</c> service profile — per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#routing-protocol-20">DIDComm Messaging v2.1 §Routing Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// Each name declares its single UTF-8 source literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property and
/// derives the interned string view through <see cref="Utf8Constants.ToInternedString"/>, matching
/// <see cref="WellKnownOutOfBandNames"/> and <see cref="WellKnownDidCommMemberNames"/>. The
/// <see cref="Profile"/> is the DIDComm Messaging <em>profile</em> string a service's <c>accept</c> array
/// lists (DIDComm v2.1 §DID Document Service Endpoint), distinct from the envelope IANA media types in
/// <see cref="DidCommMediaTypes"/> — a service profile is not a <c>Content-Type</c>.
/// </remarks>
public static class WellKnownRoutingNames
{
    /// <summary>The UTF-8 source literal of <see cref="ForwardType"/>.</summary>
    public static ReadOnlySpan<byte> ForwardTypeUtf8 => "https://didcomm.org/routing/2.0/forward"u8;

    /// <summary>
    /// The forward Message Type URI — the value of the <c>type</c> header that identifies a message as a
    /// Routing Protocol 2.0 forward message (DIDComm v2.1 §Routing Protocol 2.0 §Messages: "The only
    /// message in this protocol is the forward message.").
    /// </summary>
    public static readonly string ForwardType = Utf8Constants.ToInternedString(ForwardTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Next"/>.</summary>
    public static ReadOnlySpan<byte> NextUtf8 => "next"u8;

    /// <summary>
    /// The forward body <c>next</c> member — REQUIRED. The identifier of the party to send the attached
    /// message to, typically a DID and, for the last hop of a route, possibly a key (DIDComm v2.1
    /// §Routing Protocol 2.0 §Messages).
    /// </summary>
    public static readonly string Next = Utf8Constants.ToInternedString(NextUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Profile"/>.</summary>
    public static ReadOnlySpan<byte> ProfileUtf8 => "didcomm/v2"u8;

    /// <summary>
    /// The DIDComm Messaging v2 service profile — the value a <c>DIDCommMessaging</c> service's
    /// <c>accept</c> array lists to advertise v2 support; the sender selects the service accepting this
    /// profile (DIDComm v2.1 §DID Document Service Endpoint).
    /// </summary>
    public static readonly string Profile = Utf8Constants.ToInternedString(ProfileUtf8);
}
