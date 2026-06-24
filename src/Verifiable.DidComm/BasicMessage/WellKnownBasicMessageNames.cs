using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm.BasicMessage;

/// <summary>
/// The well-known names of the DIDComm Basic Message Protocol 2.0 — the protocol identifier URI, the
/// <c>message</c> Message Type URI, the <c>content</c> body member, and the <c>lang</c> header — per
/// <see href="https://didcomm.org/basicmessage/2.0/">DIDComm Basic Message Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// Basic Message is a didcomm.org companion protocol, NOT part of the DIDComm Messaging v2.1 core
/// specification: it carries a single human-readable text in <c>body.content</c>, with the optional
/// <c>lang</c> header naming the content's language and the standard <c>created_time</c> header carrying when
/// it was sent. Each name declares its single UTF-8 source literal as a <c>ReadOnlySpan&lt;byte&gt;</c>
/// property and derives the interned string view through <see cref="Utf8Constants.ToInternedString"/>,
/// matching <see cref="WellKnownRoutingNames"/> and the other protocol name tables.
/// </remarks>
public static class WellKnownBasicMessageNames
{
    /// <summary>The UTF-8 source literal of <see cref="BasicMessageProtocol"/>.</summary>
    public static ReadOnlySpan<byte> BasicMessageProtocolUtf8 => "https://didcomm.org/basicmessage/2.0"u8;

    /// <summary>The protocol identifier URI (PIURI) of Basic Message Protocol 2.0 (didcomm.org/basicmessage/2.0).</summary>
    public static readonly string BasicMessageProtocol = Utf8Constants.ToInternedString(BasicMessageProtocolUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MessageType"/>.</summary>
    public static ReadOnlySpan<byte> MessageTypeUtf8 => "https://didcomm.org/basicmessage/2.0/message"u8;

    /// <summary>
    /// The <c>message</c> Message Type URI — the value of the <c>type</c> header that identifies a Basic
    /// Message (didcomm.org/basicmessage/2.0 §message).
    /// </summary>
    public static readonly string MessageType = Utf8Constants.ToInternedString(MessageTypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Content"/>.</summary>
    public static ReadOnlySpan<byte> ContentUtf8 => "content"u8;

    /// <summary>
    /// The message body <c>content</c> member — REQUIRED. The human-readable text the basic message carries
    /// (didcomm.org/basicmessage/2.0 §message).
    /// </summary>
    public static readonly string Content = Utf8Constants.ToInternedString(ContentUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Lang"/>.</summary>
    public static ReadOnlySpan<byte> LangUtf8 => "lang"u8;

    /// <summary>
    /// The <c>lang</c> message header — OPTIONAL. The IETF BCP 47 language tag of the <c>content</c> text. It
    /// is a top-level header (a sibling of <c>body</c>), not a body member (didcomm.org/basicmessage/2.0
    /// §message).
    /// </summary>
    public static readonly string Lang = Utf8Constants.ToInternedString(LangUtf8);
}
