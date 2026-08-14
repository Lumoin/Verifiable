using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One PDF Signature Dictionary (ISO 32000-1 clause 12.8.1) as
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.3 profiles it: the entries the EN's own statements name, and nothing
/// else — this is not a general model of every key ISO 32000-1 admits in that dictionary (RP-1/RP-2). Clause
/// 5.3's own boundary sentence (PA-5.3-01) draws the exact line this type follows: "the entries with the
/// following keys in the Signature Dictionary are directly addressed: <c>M</c>, <c>Contents</c>, <c>Filter</c>,
/// <c>SubFilter</c>, <c>ByteRange</c>. Further the entries with the <c>Location</c>, <c>Name</c>,
/// <c>ContactInfo</c> and <c>Reason</c> keys in the Signature Dictionary are inherently addressed" — every
/// property below is one of those nine keys.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Structural, not level-conformant.</strong> This type carries what a signature dictionary's own bytes
/// state; it enforces the byte-surface invariants clause 6.3 requirement k) states for <c>ByteRange</c>
/// (PA-6.3-k, via <see cref="PdfByteRange"/>) but not Table 1's per-level presence/cardinality requirements
/// (which key must be present at which baseline level) — that reconciliation is the facts-binding stage's job,
/// composing this model rather than duplicating it.
/// </para>
/// <para>
/// <strong>Ownership.</strong> <see cref="Contents"/> is owned by this instance and disposed with it.
/// <see cref="Document"/> is a non-owning, borrowed view over memory the caller owns for at least this
/// instance's lifetime: the whole PDF byte stream is the caller's, not
/// copied here, and <see cref="FirstSignedSegment"/>/<see cref="SecondSignedSegment"/> are slices of it.
/// </para>
/// </remarks>
[DebuggerDisplay("PdfSignatureDictionary: {SubFilter.Value}, ByteRange {ByteRange.DocumentLength} bytes")]
public sealed class PdfSignatureDictionary: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a new <see cref="PdfSignatureDictionary"/>. Ownership of <paramref name="contents"/>
    /// transfers to this instance.
    /// </summary>
    /// <param name="document">See <see cref="Document"/>.</param>
    /// <param name="filter">See <see cref="Filter"/>.</param>
    /// <param name="subFilter">See <see cref="SubFilter"/>.</param>
    /// <param name="byteRange">See <see cref="ByteRange"/>.</param>
    /// <param name="contents">See <see cref="Contents"/>.</param>
    /// <param name="signingTime">See <see cref="SigningTime"/>.</param>
    /// <param name="location">See <see cref="Location"/>.</param>
    /// <param name="reason">See <see cref="Reason"/>.</param>
    /// <param name="contactInfo">See <see cref="ContactInfo"/>.</param>
    /// <param name="name">See <see cref="Name"/>.</param>
    /// <param name="objectOffset">See <see cref="ObjectOffset"/>.</param>
    /// <param name="type">See <see cref="Type"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="filter"/> or <paramref name="contents"/> is <see langword="null"/>.</exception>
    public PdfSignatureDictionary(
        ReadOnlyMemory<byte> document,
        string filter,
        PdfSubFilter subFilter,
        PdfByteRange byteRange,
        CmsSignedData contents,
        DateTimeOffset? signingTime,
        string? location,
        string? reason,
        string? contactInfo,
        string? name,
        int objectOffset,
        string? type = null)
    {
        ArgumentNullException.ThrowIfNull(filter);
        ArgumentNullException.ThrowIfNull(contents);

        Document = document;
        Filter = filter;
        SubFilter = subFilter;
        ByteRange = byteRange;
        Contents = contents;
        SigningTime = signingTime;
        Location = location;
        Reason = reason;
        ContactInfo = contactInfo;
        Name = name;
        ObjectOffset = objectOffset;
        Type = type;
    }


    /// <summary>Gets the whole PDF document's bytes this signature dictionary was located in — a non-owning, borrowed view.</summary>
    public ReadOnlyMemory<byte> Document { get; }

    /// <summary>Gets the signature handler name the <c>Filter</c> key names (PA-5.3-01). Clause 6.3 requirement j) (PA-6.3-j) permits a verifier to use a different handler than this one names, as long as it supports <see cref="SubFilter"/>.</summary>
    public string Filter { get; }

    /// <summary>Gets the <c>SubFilter</c> value, identifying the encoding convention <see cref="Contents"/> follows (PA-5.3-01; PA-6.3-l for the PAdES baseline value).</summary>
    public PdfSubFilter SubFilter { get; }

    /// <summary>Gets the <c>ByteRange</c> — the two segments of this signature's own digest-covered bytes bracketing the <see cref="Contents"/> gap (PA-5.3-01, PA-6.3-k).</summary>
    public PdfByteRange ByteRange { get; }

    /// <summary>
    /// Gets the <c>Contents</c> entry's hexadecimal string, decoded and carried as the DER-encoded CMS
    /// <c>SignedData</c> object it names (PA-4.1-01: "A DER-encoded SignedData object ... shall be included as
    /// the PDF signature in the entry with the key Contents"; PA-6.3-h). Owned by this instance.
    /// </summary>
    public CmsSignedData Contents { get; }

    /// <summary>Gets the claimed signing time the <c>M</c> entry states, or <see langword="null"/> when the entry is absent (PA-5.3-01).</summary>
    public DateTimeOffset? SigningTime { get; }

    /// <summary>Gets the <c>Location</c> entry's text, or <see langword="null"/> when absent (PA-5.3-01, "inherently addressed").</summary>
    public string? Location { get; }

    /// <summary>Gets the <c>Reason</c> entry's text, or <see langword="null"/> when absent (PA-5.3-01, "inherently addressed").</summary>
    public string? Reason { get; }

    /// <summary>Gets the <c>ContactInfo</c> entry's text, or <see langword="null"/> when absent (PA-5.3-01, "inherently addressed").</summary>
    public string? ContactInfo { get; }

    /// <summary>Gets the <c>Name</c> entry's text, or <see langword="null"/> when absent (PA-5.3-01, "inherently addressed").</summary>
    public string? Name { get; }

    /// <summary>
    /// Gets the <c>Type</c> entry's own Name value (e.g. <c>Sig</c> or <c>DocTimeStamp</c>), or <see langword="null"/>
    /// when absent. Not one of PA-5.3-01's own nine directly/inherently addressed keys — read here because clause
    /// 5.4.3's own table requires it of a Document Time-stamp dictionary specifically ("It shall be DocTimeStamp",
    /// PA-5.4.3-02), the fact <see cref="Verifiable.Cryptography.Pki.PAdESDocTimeStampValidation"/> checks.
    /// </summary>
    public string? Type { get; }

    /// <summary>
    /// Gets the byte offset of this signature's own indirect object header (<c>N G obj</c>) within <see cref="Document"/> —
    /// an independent fact from anything this dictionary's own <see cref="ByteRange"/> states, used by
    /// <see cref="PAdESSignatureValidation"/> to check an earlier signature's own claimed coverage end against
    /// where the next revision in the chain actually begins appending bytes (PA-6.3-k, the shadow-attack coverage
    /// gate).
    /// </summary>
    public int ObjectOffset { get; }

    /// <summary>Gets the first signed segment (<see cref="Document"/> bytes <c>[0, ByteRange.FirstLength)</c>) — the signed-byte-ranges view the detached-digest composition consumes.</summary>
    public ReadOnlyMemory<byte> FirstSignedSegment => Document[..ByteRange.FirstLength];

    /// <summary>Gets the second signed segment (<see cref="Document"/> bytes from <see cref="PdfByteRange.SecondOffset"/>, <see cref="PdfByteRange.SecondLength"/> long) — the signed-byte-ranges view the detached-digest composition consumes.</summary>
    public ReadOnlyMemory<byte> SecondSignedSegment => Document.Slice(ByteRange.SecondOffset, ByteRange.SecondLength);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        Contents.Dispose();
        disposed = true;
    }
}
