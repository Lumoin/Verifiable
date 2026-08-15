using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Why one <see cref="PdfSignatureDictionary"/>'s validation did not reach <see cref="Valid"/> — the PAdES-side
/// rules (ETSI EN 319 142-1 Table 1's framework rows and PA-6.3-l/m1/m2) layered in front of the composed
/// <see cref="CAdESVerification.VerifyDetachedAsync"/> outcome, whose own statuses this enum extends rather than
/// duplicates.
/// </summary>
public enum PAdESSignatureStatus
{
    /// <summary>The signature and every PAdES-side and CAdES-B baseline rule verified. The only success.</summary>
    Valid,

    /// <summary>The <c>SubFilter</c> is not <c>ETSI.CAdES.detached</c> — the one value this library's normative scope supports (PA-6.3-l).</summary>
    UnsupportedSubFilter,

    /// <summary>
    /// This signature's own <c>ByteRange</c> does not cover the byte range PA-6.3-k requires for its position in
    /// the document's revision chain: the newest signature must cover the entire current document (first segment
    /// from byte 0, second segment ending exactly at EOF); an earlier signature must cover exactly the document
    /// as it existed at its own revision (its own covered end equal to the byte offset the next revision's own
    /// signature object begins at). A legitimately multi-signed document is never a violation of this rule; content
    /// appended after the newest signature's own coverage — the shadow attack this status exists to catch — is.
    /// </summary>
    IncompleteByteRangeCoverage,

    /// <summary>The Signature Dictionary carries no <c>M</c> entry — PA-6.3-T12/g) require the claimed signing time to always be present.</summary>
    MissingSigningTime,

    /// <summary>The CMS carries a <c>signing-time</c> signed attribute — PA-6.3-T13 gives it cardinality 0, since the <c>M</c> entry already states it.</summary>
    ProhibitedSigningTimeAttribute,

    /// <summary>The CMS signature over the signed attributes, including the message-digest binding against the <c>ByteRange</c>-gapped bytes, did not verify.</summary>
    InvalidSignature,

    /// <summary>The mandatory <c>content-type</c> signed attribute is absent (PA-6.3-T02, CAdES-deferred).</summary>
    MissingContentType,

    /// <summary>The <c>signing-certificate-v2</c> signed attribute is absent (PA-6.3-T09/T10, CAdES-deferred).</summary>
    MissingSigningCertificate,

    /// <summary>The <c>signing-certificate-v2</c> hash does not match the signer certificate.</summary>
    SigningCertificateMismatch,

    /// <summary>The <c>signing-certificate-v2</c> hash algorithm is not supported.</summary>
    UnsupportedHashAlgorithm,

    /// <summary>A <c>signature-time-stamp</c> is present (PA-6.3-T24) but its own signature does not verify.</summary>
    InvalidTimestamp,

    /// <summary>A <c>signature-time-stamp</c> is present but its message imprint does not bind the signature value.</summary>
    TimestampImprintMismatch,

    /// <summary>A signed attribute could not be parsed.</summary>
    Malformed,

    /// <summary>
    /// The <c>Contents</c> entry's own decoded bytes do not trim to a well-formed DER <c>SignedData</c> followed
    /// by nothing but zero octets — a non-zero trailing octet is the smuggling vector the reserved-capacity
    /// padding convention (ISO 32000-1 clause 7.3.4) must never open (see <see cref="PAdESSignatureFacts.TryTrimToDerLength"/>).
    /// </summary>
    InvalidContentsPadding
}


/// <summary>
/// The Unverified-to-Verified promotion (RP-4) of one <see cref="PdfSignatureDictionary"/>: the PAdES-side
/// rules composed over <see cref="CAdESVerification.VerifyDetachedAsync"/>'s own CAdES-B/B-T outcome. Mint-only
/// (internal factories) — mirrors <c>CBAdESCoseSignSignerValidationResult</c>'s own mint-only rationale.
/// </summary>
/// <remarks>
/// <strong>Failures keep decoded facts.</strong> <see cref="SigningTime"/> — the Signature Dictionary's own
/// <c>M</c> entry, Unverified carriage — survives every failure that reaches past
/// <see cref="PAdESSignatureStatus.MissingSigningTime"/>, even a cryptographic one; only
/// <see cref="CryptographicResult"/> and the properties it backs are meaningful solely when
/// <see cref="IsValid"/>.
/// </remarks>
[DebuggerDisplay("PAdESSignatureValidationResult: {Status}")]
public sealed class PAdESSignatureValidationResult: IDisposable
{
    private bool disposed;


    private PAdESSignatureValidationResult(
        PAdESSignatureStatus status, DateTimeOffset? signingTime, CAdESVerificationResult? cryptographicResult, PdfByteRange byteRange, bool coversDocumentEnd)
    {
        Status = status;
        SigningTime = signingTime;
        CryptographicResult = cryptographicResult;
        ByteRange = byteRange;
        CoversDocumentEnd = coversDocumentEnd;
    }


    /// <summary>Gets the outcome; <see cref="PAdESSignatureStatus.Valid"/> is the only success.</summary>
    public PAdESSignatureStatus Status { get; }

    /// <summary>Gets whether this signature verified against every PAdES-side and CAdES-B baseline rule.</summary>
    public bool IsValid => Status == PAdESSignatureStatus.Valid;

    /// <summary>Gets the Signature Dictionary's own claimed signing time (the <c>M</c> entry, PA-6.3-T12/g) — Unverified carriage, present whenever <see cref="Status"/> is not <see cref="PAdESSignatureStatus.MissingSigningTime"/> or <see cref="PAdESSignatureStatus.UnsupportedSubFilter"/>.</summary>
    public DateTimeOffset? SigningTime { get; }

    /// <summary>Gets the CAdES level reached — <see cref="AdESBaselineLevel.BB"/> (PAdES-B-B) or <see cref="AdESBaselineLevel.BT"/> (PAdES-B-T) — meaningful only when <see cref="IsValid"/>.</summary>
    public AdESBaselineLevel Level => CryptographicResult?.Level ?? AdESBaselineLevel.BB;

    /// <summary>Gets the trusted time a verified <c>signature-time-stamp</c> asserts, or <see langword="null"/> at PAdES-B-B.</summary>
    public DateTimeOffset? TimestampTime => CryptographicResult?.TimestampTime;

    /// <summary>Gets the signer certificate the <c>signing-certificate-v2</c> attribute bound, or <see langword="null"/> when cryptographic verification was never reached.</summary>
    public PkiCertificateMemory? SignerCertificate => CryptographicResult?.SignerCertificate;

    /// <summary>Gets the composed CAdES cryptographic outcome, or <see langword="null"/> when a PAdES-side rule (<see cref="PAdESSignatureStatus.UnsupportedSubFilter"/>/<see cref="PAdESSignatureStatus.MissingSigningTime"/>) failed before it was reached. Owned by this instance.</summary>
    public CAdESVerificationResult? CryptographicResult { get; }

    /// <summary>Gets this signature's own <c>ByteRange</c> — the raw PA-6.3-k coverage fact, exposed regardless of <see cref="Status"/> so a host can reason about coverage on its own terms.</summary>
    public PdfByteRange ByteRange { get; }

    /// <summary>
    /// Gets whether <see cref="ByteRange"/> states that its own coverage reaches the current document's actual
    /// end of file (<see cref="PdfByteRange.CoversEntireDocument(int)"/> against the document length
    /// <see cref="PAdESSignatureValidation.ValidateAsync"/> was called with) — required <see langword="true"/> for
    /// the newest signature in the document's revision chain; an expected, non-violating <see langword="false"/>
    /// for an earlier signature in a legitimately multi-signed document.
    /// </summary>
    public bool CoversDocumentEnd { get; }


    /// <summary>Mints a successful result. Ownership of <paramref name="cryptographicResult"/> transfers.</summary>
    internal static PAdESSignatureValidationResult Valid(DateTimeOffset signingTime, CAdESVerificationResult cryptographicResult, PdfByteRange byteRange, bool coversDocumentEnd) =>
        new(PAdESSignatureStatus.Valid, signingTime, cryptographicResult, byteRange, coversDocumentEnd);


    /// <summary>Mints a failed result, carrying whatever Unverified carriage and cryptographic outcome were reached before the failure.</summary>
    internal static PAdESSignatureValidationResult Failed(
        PAdESSignatureStatus status, DateTimeOffset? signingTime, PdfByteRange byteRange, bool coversDocumentEnd, CAdESVerificationResult? cryptographicResult = null) =>
        new(status, signingTime, cryptographicResult, byteRange, coversDocumentEnd);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        CryptographicResult?.Dispose();
        disposed = true;
    }
}


/// <summary>
/// The outcome of validating every Signature Dictionary a PDF document carries —
/// <see cref="PAdESSignatureValidation.ValidateAsync"/>'s own result type, the promotion-shaped (RP-4) wrapper
/// around <see cref="PdfByteSurfaceReader.Locate"/>'s Unverified carriage.
/// </summary>
/// <remarks>Ownership: owns the underlying <see cref="PdfByteSurfaceParseResult"/> and every entry of <see cref="Signatures"/>; <see cref="Dispose"/> disposes both.</remarks>
[DebuggerDisplay("PAdESValidationResult: {IsSuccess}, {Signatures?.Count} signature(s)")]
public sealed class PAdESValidationResult: IDisposable
{
    private readonly PdfByteSurfaceParseResult byteSurface;
    private bool disposed;


    private PAdESValidationResult(bool isSuccess, string? failureReason, PdfByteSurfaceParseResult byteSurface, IReadOnlyList<PAdESSignatureValidationResult>? signatures)
    {
        IsSuccess = isSuccess;
        FailureReason = failureReason;
        this.byteSurface = byteSurface;
        Signatures = signatures;
    }


    /// <summary>Gets whether the document's byte surface could be located (<see cref="PdfByteSurfaceParseResult.IsSuccess"/>). When <see langword="false"/>, <see cref="Signatures"/> is <see langword="null"/>.</summary>
    public bool IsSuccess { get; }

    /// <summary>Gets why locating failed, or <see langword="null"/> when <see cref="IsSuccess"/> is <see langword="true"/>.</summary>
    public string? FailureReason { get; }

    /// <summary>Gets every located signature's own validation outcome, in document order, or <see langword="null"/> when <see cref="IsSuccess"/> is <see langword="false"/>. Owned by this instance.</summary>
    public IReadOnlyList<PAdESSignatureValidationResult>? Signatures { get; }


    /// <summary>Mints a successful result. Ownership of <paramref name="byteSurface"/> and every entry of <paramref name="signatures"/> transfers.</summary>
    internal static PAdESValidationResult Success(PdfByteSurfaceParseResult byteSurface, IReadOnlyList<PAdESSignatureValidationResult> signatures) =>
        new(true, null, byteSurface, signatures);


    /// <summary>Mints a failed result carrying no per-signature outcome. Ownership of <paramref name="byteSurface"/> transfers.</summary>
    internal static PAdESValidationResult Failure(PdfByteSurfaceParseResult byteSurface, string reason) =>
        new(false, reason, byteSurface, null);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        byteSurface.Dispose();
        if(Signatures is not null)
        {
            for(int i = 0; i < Signatures.Count; ++i)
            {
                Signatures[i].Dispose();
            }
        }

        disposed = true;
    }
}


/// <summary>
/// Validates PAdES-B-B and PAdES-B-T signatures
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see>) by composing the byte-surface reader (RP-1) with the shipped CAdES detached
/// verification surface (RP-3): locate every Signature Dictionary, check its own <c>ByteRange</c> coverage against
/// its position in the document's revision chain (PA-6.3-k, the shadow-attack gate), extract its own
/// <c>ByteRange</c>-gapped bytes as the detached content, verify through
/// <see cref="CAdESVerification.VerifyDetachedAsync"/>, and apply the PAdES-specific framework rules that surface
/// does not itself know about (PA-6.3-l/T12/T13).
/// </summary>
public static class PAdESSignatureValidation
{
    /// <summary>
    /// Locates and validates every Signature Dictionary a PDF document carries.
    /// </summary>
    /// <param name="document">The whole PDF document's bytes. Borrowed: every carrier the result owns holds views over it, so it must outlive the returned result.</param>
    /// <param name="pool">The memory pool every carrier the returned result owns is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The validation outcome. The caller owns and disposes it.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static async ValueTask<PAdESValidationResult> ValidateAsync(
        ReadOnlyMemory<byte> document,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(pool);

        PdfByteSurfaceParseResult located = PdfByteSurfaceReader.Locate(document, pool);
        if(!located.IsSuccess)
        {
            return PAdESValidationResult.Failure(located, located.FailureReason!);
        }

        IReadOnlyList<PdfSignatureDictionary> signatures = located.SignatureDictionaries!;
        var results = new List<PAdESSignatureValidationResult>(signatures.Count);
        for(int i = 0; i < signatures.Count; ++i)
        {
            //Discovery order is ascending object number, which is ascending revision order for every incremental
            //update this reader walks (RP-1's own /Prev-chain remarks): the last entry is the newest signature,
            //required to cover the entire current document; every earlier one is required to cover exactly the
            //document as it existed at its own revision -- the byte offset the next revision's own signature
            //object begins at (PA-6.3-k).
            bool isNewest = i == signatures.Count - 1;
            int requiredCoveredEnd = isNewest ? document.Length : signatures[i + 1].ObjectOffset;

            results.Add(await ValidateSignatureAsync(signatures[i], requiredCoveredEnd, document.Length, pool, cancellationToken).ConfigureAwait(false));
        }

        return PAdESValidationResult.Success(located, results);
    }


    /// <summary>Validates one located Signature Dictionary: PA-6.3-k's coverage gate, PA-6.3-l, PA-6.3-T12, the composed CAdES detached verification, and PA-6.3-T13.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TryTrimToDerLength's own [NotNullWhen(true)] out parameter creates nothing on its false return (the branch this method returns from immediately, without a using); its true return is disposed by the using(trimmedContents) block immediately below, on every path out of it — the analyzer does not trace disposal through a Try-pattern out-parameter's own conditional creation.")]
    private static async ValueTask<PAdESSignatureValidationResult> ValidateSignatureAsync(
        PdfSignatureDictionary signature, int requiredCoveredEnd, int documentLength, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        PdfByteRange byteRange = signature.ByteRange;
        //The covered-to-EOF fact is always measured against the document's own true, current length -- distinct
        //from requiredCoveredEnd, which is measured against this signature's own required position in the
        //revision chain (the next signature's own object offset for an earlier signature).
        bool coversDocumentEnd = byteRange.CoversEntireDocument(documentLength);

        //PA-6.3-k, checked before anything else: content appended after the newest signature's own coverage (the
        //shadow attack) never touches the signed bytes themselves, so cryptographic verification alone would not
        //catch it -- this is its own status, never folded into InvalidSignature.
        if(byteRange.DocumentLength != requiredCoveredEnd)
        {
            return PAdESSignatureValidationResult.Failed(PAdESSignatureStatus.IncompleteByteRangeCoverage, signature.SigningTime, byteRange, coversDocumentEnd);
        }

        if(signature.SubFilter != PdfSubFilter.EtsiCAdESDetached)
        {
            return PAdESSignatureValidationResult.Failed(PAdESSignatureStatus.UnsupportedSubFilter, signature.SigningTime, byteRange, coversDocumentEnd);
        }

        if(signature.SigningTime is not { } signingTime)
        {
            return PAdESSignatureValidationResult.Failed(PAdESSignatureStatus.MissingSigningTime, null, byteRange, coversDocumentEnd);
        }

        //PA-6.3-h's own reserved-capacity convention means signature.Contents is a well-formed DER SignedData
        //possibly followed by trailing zero-padding octets (ISO 32000-1 clause 7.3.4) -- never a second, smuggled
        //structure. Bounding the bytes handed to the composed CAdES surface to exactly the all-zero-verified DER
        //length here is what lets ManagedCmsVerification's own whole-buffer trailing-data check run everywhere
        //else without carving out PAdES-specific tolerance at that lower layer.
        if(!PAdESSignatureFacts.TryTrimToDerLength(signature.Contents, pool, out CmsSignedData? trimmedContents))
        {
            return PAdESSignatureValidationResult.Failed(PAdESSignatureStatus.InvalidContentsPadding, signingTime, byteRange, coversDocumentEnd);
        }

        using(trimmedContents)
        {
            using SignedContentMemory detachedContent = BuildByteRangeContent(signature, pool);
            CAdESVerificationResult cryptographic = await CAdESVerification.VerifyDetachedAsync(
                trimmedContents, detachedContent, pool, cancellationToken).ConfigureAwait(false);

            if(!cryptographic.IsValid)
            {
                PAdESSignatureStatus status = MapStatus(cryptographic.Status);
                cryptographic.Dispose();

                return PAdESSignatureValidationResult.Failed(status, signingTime, byteRange, coversDocumentEnd);
            }

            if(cryptographic.SigningTime is not null)
            {
                //PA-6.3-T13, cardinality 0: the CMS signing-time attribute duplicates the M entry this method
                //already required above and shall not be present.
                cryptographic.Dispose();

                return PAdESSignatureValidationResult.Failed(PAdESSignatureStatus.ProhibitedSigningTimeAttribute, signingTime, byteRange, coversDocumentEnd);
            }

            return PAdESSignatureValidationResult.Valid(signingTime, cryptographic, byteRange, coversDocumentEnd);
        }
    }


    /// <summary>
    /// Concatenates a signature's own two signed segments into one pooled carrier — the detached content
    /// <see cref="CAdESVerification.VerifyDetachedAsync"/> consumes, and — internal, reused by
    /// <see cref="PAdESSignatureFacts"/> — the same octets the format-neutral engine's own
    /// <see cref="SignerDocumentReference.Content"/> carries for one Signature Dictionary's own facts extraction.
    /// </summary>
    internal static SignedContentMemory BuildByteRangeContent(PdfSignatureDictionary signature, BaseMemoryPool pool)
    {
        int firstLength = signature.ByteRange.FirstLength;
        int secondLength = signature.ByteRange.SecondLength;
        int total = firstLength + secondLength;

        using IMemoryOwner<byte> concatenation = pool.Rent(total);
        signature.FirstSignedSegment.CopyTo(concatenation.Memory);
        signature.SecondSignedSegment.CopyTo(concatenation.Memory[firstLength..]);

        return SignedContentMemory.FromBytes(concatenation.Memory.Span[..total], pool);
    }


    /// <summary>Maps the composed CAdES detached-verification outcome onto the PAdES status vocabulary.</summary>
    private static PAdESSignatureStatus MapStatus(CAdESVerificationStatus status) => status switch
    {
        CAdESVerificationStatus.MissingContentType => PAdESSignatureStatus.MissingContentType,
        CAdESVerificationStatus.MissingSigningCertificate => PAdESSignatureStatus.MissingSigningCertificate,
        CAdESVerificationStatus.SigningCertificateMismatch => PAdESSignatureStatus.SigningCertificateMismatch,
        CAdESVerificationStatus.UnsupportedHashAlgorithm => PAdESSignatureStatus.UnsupportedHashAlgorithm,
        CAdESVerificationStatus.InvalidTimestamp => PAdESSignatureStatus.InvalidTimestamp,
        CAdESVerificationStatus.TimestampImprintMismatch => PAdESSignatureStatus.TimestampImprintMismatch,
        CAdESVerificationStatus.Malformed => PAdESSignatureStatus.Malformed,
        _ => PAdESSignatureStatus.InvalidSignature
    };
}
