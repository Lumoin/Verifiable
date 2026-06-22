namespace Verifiable.DidComm;

/// <summary>
/// The reason a DIDComm forward message failed to unpack, or <see cref="None"/> when it unpacked
/// (DIDComm Messaging v2.1 §Routing Protocol 2.0).
/// </summary>
/// <remarks>
/// Fail-closed: every value other than <see cref="None"/> denotes a rejected forward whose contents
/// MUST NOT be acted on. The mediator path is over attacker-controlled wire input, so every malformed or
/// non-conformant outcome is a typed value here, never a thrown exception.
/// </remarks>
public enum ForwardUnpackError
{
    /// <summary>The forward unpacked; its <c>next</c> and forwarded message may be used.</summary>
    None = 0,

    /// <summary>The outer envelope did not anoncrypt-decrypt — it was not addressed to this mediator, was tampered with, or is not a parseable encrypted message.</summary>
    EnvelopeUnpackFailed,

    /// <summary>The decrypted plaintext's <c>type</c> is not the forward Message Type URI (DIDComm v2.1 §Routing Protocol 2.0 §Messages).</summary>
    NotAForwardMessage,

    /// <summary>The forward body lacks the REQUIRED <c>next</c> member (DIDComm v2.1 §Routing Protocol 2.0 §Messages: "next - REQUIRED").</summary>
    MissingNext,

    /// <summary>The forward does not carry exactly one attachment whose <c>data.base64</c> holds the forwarded message (DIDComm v2.1 §Routing Protocol 2.0 §Messages: "attachments - REQUIRED").</summary>
    MissingForwardedMessage,

    /// <summary>The forwarded inline content is malformed — invalid base64url, an unserializable <c>data.json</c>, a length over the bound, or <c>links</c> present without the REQUIRED <c>hash</c>.</summary>
    MalformedForwardedMessage,

    /// <summary>The forwarded message is referenced via <c>links</c> but could not be obtained — every location was denied by policy, none was reachable, the fetched body was over-size, the integrity <c>hash</c> did not verify, or no outbound transport was supplied.</summary>
    ForwardedMessageFetchFailed
}


/// <summary>
/// The outcome of a mediator unpacking a DIDComm forward message — the next hop and the still-encrypted
/// forwarded message to re-transmit when <see cref="IsForwarded"/> is <see langword="true"/>, or an
/// <see cref="Error"/> reason otherwise (DIDComm Messaging v2.1 §Routing Protocol 2.0 §Mediator Process).
/// </summary>
/// <remarks>
/// <para>
/// Mint-only: the constructor is <see langword="private"/> and the factories are
/// <see langword="internal"/>, so a successful result can only originate from this library's unpack
/// path. Mirrors <see cref="DidCommEncryptedUnpackResult"/>.
/// </para>
/// <para>
/// <strong>Trust axis vs. data axis.</strong> This is the DIDComm-assembly counterpart of
/// <c>Verifiable.Core</c>'s <c>Verified&lt;T&gt;</c> — the proof type that separates an <em>authenticated
/// outcome</em> from freely-constructible <em>wire data</em>. As with <c>Verified&lt;T&gt;</c>, possession of
/// a successful result IS the proof: the private constructor plus internal factories mean only this library's
/// unpack path can mint one, so a consumer cannot fabricate a forwarded message. It is a DIDComm-local type
/// rather than <c>Verified&lt;T&gt;</c> itself because that type's constructor is <see langword="internal"/>
/// to <c>Verifiable.Core</c> and so cannot be minted from this assembly; the sibling DIDComm verify results
/// (<see cref="DidCommSignedVerificationResult"/> and the from_prior rotation outcome) take the same shape for
/// the same reason.
/// </para>
/// <para>
/// One axis difference from a credential <c>Verified&lt;T&gt;</c>, where the wrapped value IS the verified
/// data: a forward's payload stays <em>sealed</em>. The mediator authenticates and peels only the OUTER
/// envelope; the forwarded message remains a <see cref="DidCommEncryptedMessage"/> it never opens, so the
/// proof carried here is "this envelope was unpacked", not "this payload was verified" — the sealed-data type
/// makes that explicit (a <c>Verified&lt;T&gt;</c> over the still-encrypted payload would be a false claim).
/// </para>
/// <para>
/// The mediator MUST NOT decrypt the forwarded message; it owns it as opaque bytes
/// (<see cref="ForwardedMessage"/>) for byte-for-byte re-transmission to <see cref="Next"/>. The result
/// is <see cref="IDisposable"/> because it owns that pooled buffer; dispose it once the forwarded message
/// has been transmitted.
/// </para>
/// </remarks>
public sealed class ForwardUnpackResult: IDisposable
{
    private ForwardUnpackResult(bool isForwarded, string? next, DidCommEncryptedMessage? forwardedMessage, ForwardUnpackError error)
    {
        IsForwarded = isForwarded;
        Next = next;
        ForwardedMessage = forwardedMessage;
        Error = error;
    }


    /// <summary>Whether the forward decrypted and carried a conformant <c>next</c> and forwarded message.</summary>
    public bool IsForwarded { get; }

    /// <summary>
    /// The next hop the forwarded message is transmitted to — the forward body <c>next</c>, a DID or, for
    /// the last hop, a key (DIDComm v2.1 §Routing Protocol 2.0). <see langword="null"/> when unpack failed.
    /// </summary>
    /// <remarks>
    /// This value is ATTACKER-CONTROLLED: a forward is typically anoncrypted, so the sender is not
    /// authenticated and may name any <c>next</c>. This stateless unpack primitive does not constrain it —
    /// before transmitting, the mediator MUST apply its own policy (was this recipient registered via the
    /// Mediator Coordination protocol? is the hop count / loop bounded?), which is session state this library
    /// does not hold. Treat <see cref="Next"/> as an untrusted destination, not an authorization.
    /// </remarks>
    public string? Next { get; }

    /// <summary>
    /// The still-encrypted forwarded message the mediator re-transmits to <see cref="Next"/>, owned as
    /// opaque bytes this result disposes. <see langword="null"/> when unpack failed. The mediator MUST NOT
    /// decrypt it (DIDComm v2.1 §Routing Protocol 2.0 §Roles: the mediator passes on "a blob").
    /// </summary>
    public DidCommEncryptedMessage? ForwardedMessage { get; }

    /// <summary>The reason unpack failed, or <see cref="ForwardUnpackError.None"/> when it succeeded.</summary>
    public ForwardUnpackError Error { get; }


    //Mints a successful result owning the forwarded message buffer. Internal so only the library's unpack
    //path can produce one.
    internal static ForwardUnpackResult Success(string next, DidCommEncryptedMessage forwardedMessage)
    {
        return new ForwardUnpackResult(true, next, forwardedMessage, ForwardUnpackError.None);
    }


    //Mints a failed result carrying the rejection reason and no forwarded message.
    internal static ForwardUnpackResult Failed(ForwardUnpackError error)
    {
        return new ForwardUnpackResult(false, next: null, forwardedMessage: null, error);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        ForwardedMessage?.Dispose();
    }
}
