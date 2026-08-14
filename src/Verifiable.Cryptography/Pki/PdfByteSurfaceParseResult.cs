using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The outcome of <see cref="PdfByteSurfaceReader.Locate"/> — the promotion-shaped Unverified carriage of a PDF
/// byte-surface parse (RP-4): every signature dictionary the document's cross-reference structure resolves to,
/// or an <see cref="IsSuccess"/> <see langword="false"/> failure carrying nothing, mirroring the family's other
/// parse-result carriers (<c>CBAdESSignParseResult</c>) rather than throwing on malformed input.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Locating, not verifying.</strong> A <see cref="PdfSignatureDictionary"/> reached through
/// <see cref="SignatureDictionaries"/> is decoded and byte-range-checked, never cryptographically verified —
/// this is the Unverified carriage step; minting a <see cref="Verified{T}"/> over the CAdES <c>SignedData</c>
/// each one's <see cref="PdfSignatureDictionary.Contents"/> carries is the composing stage's job, over the
/// shipped CAdES/CMS verification surface.
/// </para>
/// <para>
/// <strong>Zero results is success, not failure.</strong> A well-formed PDF that carries no signature dictionary
/// at all is a legitimate outcome — <see cref="IsSuccess"/> <see langword="true"/> with an empty
/// <see cref="SignatureDictionaries"/> — distinct from <see cref="IsSuccess"/> <see langword="false"/>, which
/// means only that the document's own cross-reference/trailer structure could not be walked at all (a malformed
/// xref chain, or a cross-reference stream this reader does not read). A signature-dictionary-shaped candidate
/// (carrying both <c>ByteRange</c> and <c>Contents</c>) that fails one of the byte-surface invariants clause 6.3
/// requirement k) states (PA-6.3-k: overlapping/out-of-bounds <c>ByteRange</c> segments, or a <c>Contents</c>
/// value that does not sit inside the <c>ByteRange</c> gap it declares) is instead excluded from
/// <see cref="SignatureDictionaries"/> and named in <see cref="SkippedCandidateReasons"/> — fail-closed per
/// candidate, not per document, so one malformed or decoy object never makes a document's own genuinely valid
/// signatures unreachable.
/// </para>
/// </remarks>
[DebuggerDisplay("PdfByteSurfaceParseResult: {IsSuccess}, {SignatureDictionaries?.Count} signature(s)")]
public sealed class PdfByteSurfaceParseResult: IDisposable
{
    private bool disposed;


    private PdfByteSurfaceParseResult(bool isSuccess, string? failureReason, IReadOnlyList<PdfSignatureDictionary>? signatureDictionaries, IReadOnlyList<string> skippedCandidateReasons)
    {
        IsSuccess = isSuccess;
        FailureReason = failureReason;
        SignatureDictionaries = signatureDictionaries;
        SkippedCandidateReasons = skippedCandidateReasons;
    }


    /// <summary>Gets whether the document's byte surface could be located. When <see langword="false"/>, <see cref="SignatureDictionaries"/> is <see langword="null"/>.</summary>
    public bool IsSuccess { get; }

    /// <summary>Gets what this reader could state about why locating failed, or <see langword="null"/> when <see cref="IsSuccess"/> is <see langword="true"/>.</summary>
    public string? FailureReason { get; }

    /// <summary>Gets every signature dictionary the document's cross-reference structure resolves to, in the order this reader discovered them, or <see langword="null"/> when <see cref="IsSuccess"/> is <see langword="false"/>. Owned by this instance; disposed via <see cref="Dispose"/>.</summary>
    public IReadOnlyList<PdfSignatureDictionary>? SignatureDictionaries { get; }

    /// <summary>Gets why each signature-dictionary-shaped candidate that failed to parse was skipped, in discovery order — empty when every candidate parsed cleanly, or when <see cref="IsSuccess"/> is <see langword="false"/>.</summary>
    public IReadOnlyList<string> SkippedCandidateReasons { get; }


    /// <summary>Mints a successful result. Ownership of every entry of <paramref name="signatureDictionaries"/> transfers to the returned instance.</summary>
    /// <param name="signatureDictionaries">Every signature dictionary located.</param>
    /// <param name="skippedCandidateReasons">See <see cref="SkippedCandidateReasons"/>.</param>
    /// <returns>A successful <see cref="PdfByteSurfaceParseResult"/>.</returns>
    internal static PdfByteSurfaceParseResult Success(IReadOnlyList<PdfSignatureDictionary> signatureDictionaries, IReadOnlyList<string> skippedCandidateReasons) =>
        new(true, null, signatureDictionaries, skippedCandidateReasons);


    /// <summary>Mints a failed result carrying no decoded content.</summary>
    /// <param name="reason">See <see cref="FailureReason"/>.</param>
    /// <returns>A failed <see cref="PdfByteSurfaceParseResult"/>.</returns>
    internal static PdfByteSurfaceParseResult Failure(string reason) => new(false, reason, null, []);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        if(SignatureDictionaries is not null)
        {
            for(int i = 0; i < SignatureDictionaries.Count; ++i)
            {
                SignatureDictionaries[i].Dispose();
            }
        }

        disposed = true;
    }
}
