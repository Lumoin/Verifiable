namespace Verifiable.DidComm.BasicMessage;

/// <summary>
/// The semantic content of a DIDComm Basic Message — the human-readable text and its optional language —
/// per <see href="https://didcomm.org/basicmessage/2.0/">DIDComm Basic Message Protocol 2.0</see>.
/// </summary>
/// <remarks>
/// This is the operate-on form: an application builds a <see cref="BasicMessage"/> and turns it into a wire
/// <see cref="DidCommMessage"/> via <see cref="BasicMessageExtensions.CreateBasicMessage"/>, or recovers one
/// from a received message via <see cref="BasicMessageExtensions.TryInterpretBasicMessage"/>. The send time is
/// the standard <see cref="DidCommMessage.CreatedTime"/> header (read it off the message), so it is not
/// duplicated here. Recovering this type carries no cryptographic proof — authenticity was established by the
/// envelope unpack that produced the <see cref="DidCommMessage"/>; interpretation is purely shaping wire data
/// into the typed view, which is why the read path is a plain <c>bool TryInterpret…</c>. Equality is by value
/// over <see cref="Content"/> and <see cref="Lang"/> (ordinal), the record default.
/// </remarks>
public sealed record BasicMessage
{
    /// <summary>REQUIRED. The human-readable text the message carries (didcomm.org/basicmessage/2.0 §message).</summary>
    public required string Content { get; init; }

    /// <summary>
    /// OPTIONAL. The IETF BCP 47 language tag of <see cref="Content"/>, conveyed as the top-level <c>lang</c>
    /// header (didcomm.org/basicmessage/2.0 §message).
    /// </summary>
    public string? Lang { get; init; }
}
