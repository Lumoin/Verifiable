using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Why one located Document Time-stamp did not reach <see cref="Valid"/> — the PAdES-side rules (ETSI EN 319 142-1
/// clause 5.4.3) layered in front of the RFC 3161 token check <see cref="TimestampTokenInfo"/> performs.
/// </summary>
public enum PAdESDocTimeStampStatus
{
    /// <summary>The Document Time-stamp and its own RFC 3161 token verified. The only success.</summary>
    Valid,

    /// <summary>
    /// This Document Time-stamp's own <c>ByteRange</c> does not cover the byte range PA-5.4.3-07 requires for its
    /// position in the document's revision chain — the same shadow-attack coverage gate <c>PAdESSignatureValidation</c>
    /// applies to an ordinary signature (PA-6.3-k).
    /// </summary>
    IncompleteByteRangeCoverage,

    /// <summary>The dictionary's <c>Type</c> entry is absent or is not <c>DocTimeStamp</c> (PA-5.4.3-02: "It shall be DocTimeStamp", a Required key).</summary>
    InvalidType,

    /// <summary>The <c>TimeStampToken</c>'s own CMS signature did not verify, or its <c>TSTInfo</c> could not be read.</summary>
    InvalidToken,

    /// <summary>The token's <c>messageImprint</c> does not match the digest of this Document Time-stamp's own <c>ByteRange</c>-gapped bytes (PA-5.4.3-06).</summary>
    TokenImprintMismatch
}


/// <summary>
/// The Unverified-to-Verified promotion (RP-4) of one Document Time-stamp: the PAdES-side coverage/type rules
/// composed with an RFC 3161 token check.
/// </summary>
/// <remarks>Mint-only (internal factories), mirroring <c>PAdESSignatureValidationResult</c>'s own rationale.</remarks>
[DebuggerDisplay("PAdESDocTimeStampValidationResult: {Status}")]
public sealed class PAdESDocTimeStampValidationResult: IDisposable
{
    private bool disposed;


    private PAdESDocTimeStampValidationResult(PAdESDocTimeStampStatus status, TimestampTokenInfo? tokenInfo, PdfByteRange byteRange, bool coversDocumentEnd)
    {
        Status = status;
        TokenInfo = tokenInfo;
        ByteRange = byteRange;
        CoversDocumentEnd = coversDocumentEnd;
    }


    /// <summary>Gets the outcome; <see cref="PAdESDocTimeStampStatus.Valid"/> is the only success.</summary>
    public PAdESDocTimeStampStatus Status { get; }

    /// <summary>Gets whether this Document Time-stamp verified against every rule this type checks.</summary>
    public bool IsValid => Status == PAdESDocTimeStampStatus.Valid;

    /// <summary>Gets the trusted time the token asserts, meaningful only when <see cref="IsValid"/>.</summary>
    public DateTimeOffset? GenerationTime => TokenInfo?.GenerationTime;

    /// <summary>Gets the already-read <c>TSTInfo</c> facts, or <see langword="null"/> when the token could not be opened at all. Owned by this instance.</summary>
    public TimestampTokenInfo? TokenInfo { get; }

    /// <summary>Gets this Document Time-stamp's own <c>ByteRange</c> — the raw PA-5.4.3-07 coverage fact, exposed regardless of <see cref="Status"/>.</summary>
    public PdfByteRange ByteRange { get; }

    /// <summary>Gets whether <see cref="ByteRange"/> states that its own coverage reaches the current document's actual end of file.</summary>
    public bool CoversDocumentEnd { get; }


    /// <summary>Mints a successful result. Ownership of <paramref name="tokenInfo"/> transfers.</summary>
    internal static PAdESDocTimeStampValidationResult Valid(TimestampTokenInfo tokenInfo, PdfByteRange byteRange, bool coversDocumentEnd) =>
        new(PAdESDocTimeStampStatus.Valid, tokenInfo, byteRange, coversDocumentEnd);


    /// <summary>Mints a failed result, carrying whatever token facts were reached before the failure. Ownership of <paramref name="tokenInfo"/>, when supplied, transfers.</summary>
    internal static PAdESDocTimeStampValidationResult Failed(
        PAdESDocTimeStampStatus status, PdfByteRange byteRange, bool coversDocumentEnd, TimestampTokenInfo? tokenInfo = null) =>
        new(status, tokenInfo, byteRange, coversDocumentEnd);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        TokenInfo?.Dispose();
        disposed = true;
    }
}


/// <summary>
/// The outcome of validating every Document Time-stamp a PDF document carries — <see cref="PAdESDocTimeStampValidation.ValidateAsync"/>'s
/// own result type, the promotion-shaped (RP-4) wrapper around <see cref="PdfByteSurfaceReader.Locate"/>'s
/// Unverified carriage.
/// </summary>
/// <remarks>Ownership: owns the underlying <see cref="PdfByteSurfaceParseResult"/> and every entry of <see cref="DocTimeStamps"/>; <see cref="Dispose"/> disposes both.</remarks>
[DebuggerDisplay("PAdESDocTimeStampCollectionResult: {IsSuccess}, {DocTimeStamps?.Count} time-stamp(s)")]
public sealed class PAdESDocTimeStampCollectionResult: IDisposable
{
    private PdfByteSurfaceParseResult ByteSurface { get; }
    private bool disposed;


    private PAdESDocTimeStampCollectionResult(bool isSuccess, string? failureReason, PdfByteSurfaceParseResult byteSurface, IReadOnlyList<PAdESDocTimeStampValidationResult>? docTimeStamps)
    {
        IsSuccess = isSuccess;
        FailureReason = failureReason;
        this.ByteSurface = byteSurface;
        DocTimeStamps = docTimeStamps;
    }


    /// <summary>Gets whether the document's byte surface could be located. When <see langword="false"/>, <see cref="DocTimeStamps"/> is <see langword="null"/>.</summary>
    public bool IsSuccess { get; }

    /// <summary>Gets why locating failed, or <see langword="null"/> when <see cref="IsSuccess"/> is <see langword="true"/>.</summary>
    public string? FailureReason { get; }

    /// <summary>Gets every located Document Time-stamp's own validation outcome, in document (revision) order, or <see langword="null"/> when <see cref="IsSuccess"/> is <see langword="false"/>. Owned by this instance.</summary>
    public IReadOnlyList<PAdESDocTimeStampValidationResult>? DocTimeStamps { get; }


    /// <summary>Mints a successful result. Ownership of <paramref name="byteSurface"/> and every entry of <paramref name="docTimeStamps"/> transfers.</summary>
    internal static PAdESDocTimeStampCollectionResult Success(PdfByteSurfaceParseResult byteSurface, IReadOnlyList<PAdESDocTimeStampValidationResult> docTimeStamps) =>
        new(true, null, byteSurface, docTimeStamps);


    /// <summary>Mints a failed result carrying no per-time-stamp outcome. Ownership of <paramref name="byteSurface"/> transfers.</summary>
    internal static PAdESDocTimeStampCollectionResult Failure(PdfByteSurfaceParseResult byteSurface, string reason) =>
        new(false, reason, byteSurface, null);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        ByteSurface.Dispose();
        if(DocTimeStamps is not null)
        {
            for(int i = 0; i < DocTimeStamps.Count; ++i)
            {
                DocTimeStamps[i].Dispose();
            }
        }

        disposed = true;
    }
}


/// <summary>
/// Validates PAdES Document Time-stamps
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.4.3) by composing <see cref="PdfByteSurfaceReader"/> (RP-1: the same
/// {<c>ByteRange</c>, <c>Contents</c>}-shaped candidate discovery <c>PAdESSignatureValidation</c> composes,
/// discriminated here by <see cref="PdfSubFilter.EtsiRfc3161"/> rather than <see cref="PdfSubFilter.EtsiCAdESDetached"/>)
/// with <see cref="TimestampTokenInfo.ReadFromTokenAsync"/>: locate every candidate, check its own <c>ByteRange</c>
/// coverage against its position in the document's revision chain (PA-5.4.3-07, the same shadow-attack gate
/// PA-6.3-k states for an ordinary signature), open and verify its <c>TimeStampToken</c>, and check the token's
/// own <c>messageImprint</c> against the digest of the <c>ByteRange</c>-gapped bytes (PA-5.4.3-06).
/// </summary>
public static class PAdESDocTimeStampValidation
{
    /// <summary>
    /// Locates and validates every Document Time-stamp a PDF document carries.
    /// </summary>
    /// <param name="document">The whole PDF document's bytes. Borrowed: every carrier the result owns holds views over it, so it must outlive the returned result.</param>
    /// <param name="pool">The memory pool every carrier the returned result owns is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The validation outcome. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<PAdESDocTimeStampCollectionResult> ValidateAsync(
        ReadOnlyMemory<byte> document,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(document, pool);
        if(!located.IsSuccess)
        {
            return PAdESDocTimeStampCollectionResult.Failure(located, located.FailureReason!);
        }

        IReadOnlyList<PdfSignatureDictionary> candidates = located.SignatureDictionaries!;
        var results = new List<PAdESDocTimeStampValidationResult>();
        for(int i = 0; i < candidates.Count; ++i)
        {
            if(candidates[i].SubFilter != PdfSubFilter.EtsiRfc3161)
            {
                //Not a Document Time-stamp candidate — an ordinary PAdES signature, PAdESSignatureValidation's own territory.
                continue;
            }

            //Chain position is computed against the FULL located list (every ByteRange-bearing object, signatures
            //and document time-stamps together) — the same "next object's offset" rule PAdESSignatureValidation
            //applies, since a document's revision chain interleaves both kinds.
            bool isNewest = i == candidates.Count - 1;
            int requiredCoveredEnd = isNewest ? document.Length : candidates[i + 1].ObjectOffset;

            results.Add(await ValidateOneAsync(candidates[i], requiredCoveredEnd, document.Length, pool, cancellationToken).ConfigureAwait(false));
        }

        return PAdESDocTimeStampCollectionResult.Success(located, results);
    }


    /// <summary>Validates one located Document Time-stamp candidate: PA-5.4.3-07's coverage gate, PA-5.4.3-02, and the RFC 3161 token check.</summary>
    private static async ValueTask<PAdESDocTimeStampValidationResult> ValidateOneAsync(
        PdfSignatureDictionary candidate, int requiredCoveredEnd, int documentLength, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        PdfByteRange byteRange = candidate.ByteRange;
        bool coversDocumentEnd = byteRange.CoversEntireDocument(documentLength);

        if(byteRange.DocumentLength != requiredCoveredEnd)
        {
            return PAdESDocTimeStampValidationResult.Failed(PAdESDocTimeStampStatus.IncompleteByteRangeCoverage, byteRange, coversDocumentEnd);
        }

        //PA-5.4.3-02: Type is a Required key of the Document Time-stamp dictionary, so absence is a violation too,
        //not merely a mismatched value.
        if(!string.Equals(candidate.Type, "DocTimeStamp", StringComparison.Ordinal))
        {
            return PAdESDocTimeStampValidationResult.Failed(PAdESDocTimeStampStatus.InvalidType, byteRange, coversDocumentEnd);
        }

        using PkiCertificateMemory token = CopyContentsToTimestampTokenCarrier(candidate.Contents, pool);
        TimestampTokenInfo tokenInfo = await TimestampTokenInfo.ReadFromTokenAsync(token, pool, cancellationToken).ConfigureAwait(false);
        if(!tokenInfo.IsRead)
        {
            return PAdESDocTimeStampValidationResult.Failed(PAdESDocTimeStampStatus.InvalidToken, byteRange, coversDocumentEnd, tokenInfo);
        }

        using IMemoryOwner<byte> byteRangeContent = BuildByteRangeContent(candidate, pool, out int byteRangeContentLength);
        bool imprintMatches = await tokenInfo.VerifyMessageImprintAsync(
            byteRangeContent.Memory[..byteRangeContentLength], pool, cancellationToken).ConfigureAwait(false);
        if(!imprintMatches)
        {
            return PAdESDocTimeStampValidationResult.Failed(PAdESDocTimeStampStatus.TokenImprintMismatch, byteRange, coversDocumentEnd, tokenInfo);
        }

        return PAdESDocTimeStampValidationResult.Valid(tokenInfo, byteRange, coversDocumentEnd);
    }


    /// <summary>Copies a candidate's own <c>Contents</c> bytes (already decoded as a CMS <c>SignedData</c> — an RFC 3161 <c>TimeStampToken</c> is structurally the same shape) into a carrier tagged for <see cref="TimestampTokenInfo.ReadFromTokenAsync"/>.</summary>
    private static PkiCertificateMemory CopyContentsToTimestampTokenCarrier(CmsSignedData contents, BaseMemoryPool pool)
    {
        ReadOnlySpan<byte> data = contents.AsReadOnlySpan();
        IMemoryOwner<byte> owner = pool.Rent(data.Length);
        try
        {
            data.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }


    /// <summary>Concatenates a candidate's own two signed segments into one pooled buffer — the raw <c>ByteRange</c>-gapped bytes <see cref="TimestampTokenInfo.VerifyMessageImprintAsync"/> hashes itself.</summary>
    private static IMemoryOwner<byte> BuildByteRangeContent(PdfSignatureDictionary candidate, BaseMemoryPool pool, out int length)
    {
        int firstLength = candidate.ByteRange.FirstLength;
        int secondLength = candidate.ByteRange.SecondLength;
        length = firstLength + secondLength;

        IMemoryOwner<byte> owner = pool.Rent(length);
        candidate.FirstSignedSegment.CopyTo(owner.Memory);
        candidate.SecondSignedSegment.CopyTo(owner.Memory[firstLength..]);

        return owner;
    }
}
