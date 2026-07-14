using System;
using System.Buffers;

namespace Verifiable.DidComm;

/// <summary>
/// Why a DIDComm attachment payload failed to resolve, or <see cref="None"/> when it resolved
/// (DIDComm Messaging v2.1 §Attachments).
/// </summary>
/// <remarks>
/// Fail-closed: every value other than <see cref="None"/> denotes a rejected attachment whose payload
/// MUST NOT be acted on. The resolver runs over attacker-controlled wire input (an inline <c>base64</c>
/// string, an embedded <c>json</c> value, or a remote <c>links</c> location), so every malformed,
/// integrity-failing, or policy-denied outcome is a typed value here, never a thrown exception.
/// </remarks>
public enum AttachmentResolutionError
{
    /// <summary>The payload resolved; the bytes may be used.</summary>
    None = 0,

    /// <summary>The <c>data</c> object carries none of the recognized access forms (DIDComm v2.1 §Attachments: "MUST contain at least one").</summary>
    MissingData,

    /// <summary>The only access form present is <c>jws</c>; a signed attachment is a different trust axis and is out of scope for this payload resolver.</summary>
    JwsResolutionNotSupported,

    /// <summary>The <c>data</c> object references content via <c>links</c> but carries no <c>hash</c> — REQUIRED for a by-reference attachment (DIDComm v2.1 §Attachments: "MUST be used if the data is referenced via the links").</summary>
    HashMissingForLinks,

    /// <summary>The <c>hash</c> decodes but its self-describing multihash algorithm code is one the supplied <see cref="HashFunctionSelector"/> does not map to a hash function — the algorithm choice lives in the data, never hardcoded, so an unsupported code is rejected rather than guessed (a typical selector supports sha2-256).</summary>
    UnsupportedHashAlgorithm,

    /// <summary>The <c>hash</c> string is not a decodable multihash of the expected length.</summary>
    MalformedHash,

    /// <summary>An inline form (<c>base64</c> or <c>json</c>) is present but does not decode/serialize — a HARD FAIL that never falls back to fetch.</summary>
    MalformedInline,

    /// <summary>The resolved content's digest — recomputed with the hash function the <see cref="HashFunctionSelector"/> returned for the multihash's algorithm code — does not match the multihash <c>hash</c>; an integrity failure, so the bytes are NOT returned.</summary>
    HashMismatch,

    /// <summary>Every <c>links</c> location was denied by the outbound-fetch policy (the SSRF gate) — none was contacted.</summary>
    FetchDenied,

    /// <summary>Each <c>links</c> location was reachable but none yielded a fetched, size-bounded, hash-verified body.</summary>
    AllLinksFailed
}


/// <summary>
/// Where a resolved DIDComm attachment payload came from (DIDComm Messaging v2.1 §Attachments).
/// </summary>
public enum AttachmentResolutionSource
{
    /// <summary>The payload was carried by value, inline in the <c>data</c> object (<c>base64</c> or <c>json</c>).</summary>
    Inline = 0,

    /// <summary>The payload was carried by reference and fetched from a <c>links</c> location.</summary>
    Fetched
}


/// <summary>
/// The outcome of resolving a DIDComm attachment's <c>data</c> object to its payload bytes — the owned
/// payload and where it came from when <see cref="IsResolved"/> is <see langword="true"/>, or an
/// <see cref="Error"/> reason otherwise (DIDComm Messaging v2.1 §Attachments).
/// </summary>
/// <remarks>
/// <para>
/// Mint-only: the constructor is <see langword="private"/> and the factories are
/// <see langword="internal"/>, so a resolved result can only originate from this library's resolver path.
/// Mirrors <see cref="ForwardUnpackResult"/>.
/// </para>
/// <para>
/// Possession of a resolved result IS the proof the payload passed the access-form precedence and — for a
/// by-reference attachment or a hashed inline one — the multihash integrity check. The bytes are exposed
/// as <see cref="ReadOnlyMemory{T}"/>, never as a naked array. The result is <see cref="IDisposable"/>
/// because it owns the pooled payload buffer; dispose it once the payload has been consumed.
/// </para>
/// </remarks>
public sealed class AttachmentResolutionResult: IDisposable
{
    private IMemoryOwner<byte>? PayloadOwner { get; }
    private int PayloadLength { get; }


    private AttachmentResolutionResult(
        bool isResolved,
        IMemoryOwner<byte>? payloadOwner,
        int payloadLength,
        AttachmentResolutionSource source,
        Uri? resolvedFrom,
        AttachmentResolutionError error)
    {
        IsResolved = isResolved;
        this.PayloadOwner = payloadOwner;
        this.PayloadLength = payloadLength;
        Source = source;
        ResolvedFrom = resolvedFrom;
        Error = error;
    }


    /// <summary>Whether the attachment payload resolved and passed every applicable integrity check.</summary>
    public bool IsResolved { get; }

    /// <summary>
    /// The resolved payload bytes, owned by this result and released on <see cref="Dispose"/>. Empty when
    /// resolution failed. Exposed as <see cref="ReadOnlyMemory{T}"/> — never as a naked array.
    /// </summary>
    public ReadOnlyMemory<byte> Payload =>
        PayloadOwner is null ? ReadOnlyMemory<byte>.Empty : PayloadOwner.Memory[..PayloadLength];

    /// <summary>Whether the payload was carried by value (inline) or fetched by reference. Meaningful only when <see cref="IsResolved"/>.</summary>
    public AttachmentResolutionSource Source { get; }

    /// <summary>
    /// The <c>links</c> location the payload was fetched from when <see cref="Source"/> is
    /// <see cref="AttachmentResolutionSource.Fetched"/>; <see langword="null"/> for an inline payload or a
    /// failed resolution.
    /// </summary>
    public Uri? ResolvedFrom { get; }

    /// <summary>The reason resolution failed, or <see cref="AttachmentResolutionError.None"/> when it succeeded.</summary>
    public AttachmentResolutionError Error { get; }


    //Mints a resolved result owning the inline payload buffer. Internal so only the library's resolver path
    //can produce one.
    internal static AttachmentResolutionResult ResolvedInline(IMemoryOwner<byte> payloadOwner, int payloadLength)
    {
        ArgumentNullException.ThrowIfNull(payloadOwner);

        return new AttachmentResolutionResult(
            isResolved: true,
            payloadOwner,
            payloadLength,
            AttachmentResolutionSource.Inline,
            resolvedFrom: null,
            AttachmentResolutionError.None);
    }


    //Mints a resolved result owning a fetched payload buffer, recording the link it was fetched from.
    internal static AttachmentResolutionResult ResolvedFetched(IMemoryOwner<byte> payloadOwner, int payloadLength, Uri resolvedFrom)
    {
        ArgumentNullException.ThrowIfNull(payloadOwner);
        ArgumentNullException.ThrowIfNull(resolvedFrom);

        return new AttachmentResolutionResult(
            isResolved: true,
            payloadOwner,
            payloadLength,
            AttachmentResolutionSource.Fetched,
            resolvedFrom,
            AttachmentResolutionError.None);
    }


    //Mints a failed result carrying the rejection reason and no payload.
    internal static AttachmentResolutionResult Failed(AttachmentResolutionError error)
    {
        return new AttachmentResolutionResult(
            isResolved: false,
            payloadOwner: null,
            payloadLength: 0,
            AttachmentResolutionSource.Inline,
            resolvedFrom: null,
            error);
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        PayloadOwner?.Dispose();
    }
}
