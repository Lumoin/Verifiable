using Verifiable.Cryptography.Text;

namespace Verifiable.DidComm;

/// <summary>
/// The well-known name of the DIDComm Empty Message — the <c>empty</c> Message Type URI — per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#the-empty-message">DIDComm Messaging v2.1 §The Empty Message</see>.
/// </summary>
/// <remarks>
/// The empty message has no semantic meaning; its only purpose is to carry message headers when there is
/// no body content to attach them to. It is the spec-recommended carrier for a pure acknowledgment — an
/// empty message with an <c>ack</c> header (DIDComm v2.1 §ACKs). The name declares its single UTF-8 source
/// literal as a <c>ReadOnlySpan&lt;byte&gt;</c> property and derives the interned string view through
/// <see cref="Utf8Constants.ToInternedString"/>, matching <see cref="WellKnownRoutingNames"/> and
/// <see cref="WellKnownDidCommMemberNames"/>.
/// </remarks>
public static class WellKnownEmptyMessageNames
{
    /// <summary>The UTF-8 source literal of <see cref="EmptyType"/>.</summary>
    public static ReadOnlySpan<byte> EmptyTypeUtf8 => "https://didcomm.org/empty/1.0/empty"u8;

    /// <summary>
    /// The empty Message Type URI — the value of the <c>type</c> header that identifies a message as the
    /// DIDComm Empty Message, whose <c>body</c> is the empty object <c>{}</c> (DIDComm v2.1 §The Empty Message).
    /// </summary>
    public static readonly string EmptyType = Utf8Constants.ToInternedString(EmptyTypeUtf8);
}
