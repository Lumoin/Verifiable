using System.Collections.Generic;

namespace Verifiable.DidComm;

/// <summary>
/// A DIDComm plaintext message — a JWM (JSON Web Message) carrying application-level content and
/// the headers common across message types, as defined in
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#plaintext-message-structure">DIDComm Messaging v2.1 §Plaintext Message Structure</see>
/// and §Message Headers.
/// </summary>
/// <remarks>
/// <para>
/// This is the application-facing form that higher-level protocols build on; it is normally
/// wrapped in a signed or encrypted envelope before transport. The predefined headers below are a
/// modest fixed inventory; additional, unreserved header names MAY be present and are carried in
/// <see cref="AdditionalHeaders"/>. Software that does not understand an extension header MUST
/// ignore it and MUST NOT fail because of its inclusion (DIDComm v2.1 §Message Headers).
/// </para>
/// <para>
/// The model is a settable POCO so it can be a serialization target; the concrete JSON
/// (de)serialization lives in the leaf serialization package, supplied to pack/unpack through the
/// serializer and parser delegates.
/// </para>
/// </remarks>
public sealed class DidCommMessage
{
    /// <summary>
    /// REQUIRED. The message id, which MUST be unique to the sender across all messages they send.
    /// See DIDComm v2.1 §Threading for constraints on this value.
    /// </summary>
    public string? Id { get; set; }

    /// <summary>
    /// REQUIRED. A Message Type URI associating the <see cref="Body"/> with a published, versioned
    /// schema, used to map the message to a handler.
    /// </summary>
    public string? Type { get; set; }

    /// <summary>
    /// OPTIONAL. Identifiers for the recipients — each a DID or DID URL without the fragment
    /// component. Recipients use these to learn which of their keys can decrypt and who else the
    /// message was addressed to. Not usable for routing (it is encrypted at every intermediate hop).
    /// </summary>
    public IList<string>? To { get; set; }

    /// <summary>
    /// OPTIONAL when the message is anoncrypted; REQUIRED when authcrypted. The sender identifier —
    /// a DID or DID URL without the fragment component. When encrypted, the sender key MUST be
    /// authorized for encryption by this DID.
    /// </summary>
    public string? From { get; set; }

    /// <summary>
    /// OPTIONAL. The thread identifier uniquely identifying the thread the message belongs to. When
    /// absent, the message <see cref="Id"/> is treated as the thread id.
    /// </summary>
    public string? ThreadId { get; set; }

    /// <summary>
    /// OPTIONAL. The parent thread identifier, when this message is a child of another thread.
    /// </summary>
    public string? ParentThreadId { get; set; }

    /// <summary>
    /// The effective thread id: <see cref="ThreadId"/> when present and non-empty, otherwise <see cref="Id"/>.
    /// DIDComm v2.1 §Threading requires that "if the <c>thid</c> header is not included, the <c>id</c>
    /// of the current message MUST be used as the value" — the message starts a new thread whose id is its
    /// own <see cref="Id"/>. An empty <c>thid</c> is malformed, not a real thread, so it is treated as absent
    /// (it must NOT collapse otherwise-unrelated messages onto a single empty thread). Threading logic
    /// compares against this rather than the raw <see cref="ThreadId"/>. <see langword="null"/> only when
    /// both are absent (a malformed message).
    /// </summary>
    public string? EffectiveThreadId => string.IsNullOrEmpty(ThreadId) ? Id : ThreadId;

    /// <summary>
    /// OPTIONAL but recommended. When the sender created the message, in UTC epoch seconds.
    /// </summary>
    public long? CreatedTime { get; set; }

    /// <summary>
    /// OPTIONAL. When the sender will consider the message expired, in UTC epoch seconds. When
    /// omitted, the message has no expiration.
    /// </summary>
    public long? ExpiresTime { get; set; }

    /// <summary>
    /// REQUIRED for a DID Rotation message. A JWT whose <c>sub</c> is the new DID and <c>iss</c> is
    /// the prior DID, signed by a key authorized by the prior DID. Carried verbatim here; the
    /// rotation semantics (DIDComm v2.1 §DID Rotation) are applied by the unpack pipeline, not by
    /// this model.
    /// </summary>
    public string? FromPrior { get; set; }

    /// <summary>
    /// OPTIONAL. The ids of messages whose acknowledgment the sender requests (DIDComm v2.1 §ACKs).
    /// Each entry is the id of a message that needs acknowledgment; the empty string <c>""</c> means
    /// "the current message". The presence of this header creates no obligation on the recipient.
    /// SHOULD NOT appear on a forward message and MUST NOT be honored by a mediator.
    /// </summary>
    public IList<string>? PleaseAck { get; set; }

    /// <summary>
    /// OPTIONAL. The ids of messages being acknowledged (DIDComm v2.1 §ACKs). A message carrying this
    /// header is an explicit ACK regardless of its type. Values MUST appear in the order received by
    /// the acknowledger, from oldest to most recent.
    /// </summary>
    public IList<string>? Ack { get; set; }

    /// <summary>
    /// OPTIONAL. The application data and structure specific to the message <see cref="Type"/>.
    /// When present it MUST be a JSON object; held as arbitrary JSON.
    /// </summary>
    public IDictionary<string, object>? Body { get; set; }

    /// <summary>OPTIONAL. The message attachments.</summary>
    public IList<Attachment>? Attachments { get; set; }

    /// <summary>
    /// Extension headers beyond the predefined inventory. These are siblings of <see cref="Body"/>
    /// at the message root, carried so that an unrecognized header with a value survives a round
    /// trip and is never a cause of failure; a JSON-null-valued header conveys no value and is
    /// dropped as a legal "ignore" (DIDComm v2.1 §Message Headers).
    /// </summary>
    public IDictionary<string, object>? AdditionalHeaders { get; set; }
}
