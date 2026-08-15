using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What one <see cref="PAdESDocTimeStampCreation.CreateAsync"/> call needs: the prior document revision the
/// document time-stamp is layered on top of, and how to reach a Time-Stamping Authority.
/// </summary>
public sealed record PAdESDocTimeStampRequest
{
    /// <summary>Gets the whole bytes of the revision the document time-stamp is layered on top of.</summary>
    public required ReadOnlyMemory<byte> PriorDocument { get; init; }

    /// <summary>Gets where the prior revision's own cross-reference chain and catalog sit.</summary>
    public required PdfIncrementalUpdateAnchor Anchor { get; init; }

    /// <summary>Gets the number of raw <c>TimeStampToken</c> bytes to reserve <c>Contents</c> capacity for; must fit the token the authority returns.</summary>
    public required int ContentsCapacityBytes { get; init; }

    /// <summary>Gets the algorithm the <c>messageImprint</c> is computed under (PA-5.4.3-06), which the authority echoes in its token.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into TimestampFetchContext.TsaUri, which is deliberately a string for the same reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;

    /// <summary>Gets the signature handler name written as the <c>Filter</c> key — still required of the base Signature Dictionary shape table 14 modifies.</summary>
    public string Filter { get; init; } = "Adobe.PPKLite";
}


/// <summary>
/// The result of <see cref="PAdESDocTimeStampCreation.CreateAsync"/>: the whole document's bytes carrying the new
/// Document Time-stamp, and the object numbers a further incremental update chains onto.
/// </summary>
public sealed record PAdESDocTimeStampResult
{
    /// <summary>Gets the whole document's bytes, the new Document Time-stamp revision appended.</summary>
    public required byte[] Bytes { get; init; }

    /// <summary>Gets the new Document Time-stamp's own <c>ByteRange</c> (PA-5.4.3-07).</summary>
    public required PdfByteRange ByteRange { get; init; }

    /// <summary>Gets the byte offset of this revision's own <c>xref</c> keyword, for chaining a further incremental update's own <c>/Prev</c>.</summary>
    public required int XrefOffset { get; init; }

    /// <summary>Gets the new Document Time-stamp dictionary's own object number.</summary>
    public required int DocTimeStampObjectNumber { get; init; }

    /// <summary>Gets the anchor a further incremental update built on top of this one supplies to its own next call.</summary>
    /// <param name="rootObjectNumber">The document catalog's own object number.</param>
    /// <param name="rootGeneration">The document catalog's own generation number.</param>
    public PdfIncrementalUpdateAnchor NextAnchor(int rootObjectNumber, int rootGeneration = 0) => new()
    {
        PriorXrefOffset = XrefOffset,
        PriorObjectCount = DocTimeStampObjectNumber + 1,
        RootObjectNumber = rootObjectNumber,
        RootGeneration = rootGeneration
    };
}


/// <summary>
/// Creates a PAdES Document Time-stamp signature
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see> clause 5.4.3) by composing <see cref="PdfIncrementalUpdateWriter.AppendPlaceholderDocTimeStamp"/>
/// with the SHIPPED RFC 3161 acquisition client (<see cref="TimestampAcquisition.AcquireAsync"/>): the
/// <c>messageImprint</c> is the digest of the placeholder's own <c>ByteRange</c>-gapped document bytes
/// (PA-5.4.3-06), the same discipline <see cref="PAdESSignatureCreation"/> applies to an ordinary signature's own
/// detached content digest, and the acquired, already-verified token is embedded as <c>Contents</c> unchanged.
/// </summary>
public static class PAdESDocTimeStampCreation
{
    /// <summary>
    /// Creates a Document Time-stamp signature.
    /// </summary>
    /// <param name="request">The creation request.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The signed document and where the new Document Time-stamp landed.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="TimestampAcquisitionException">When the authority could not be reached, or the token it returned does not verify.</exception>
    public static async ValueTask<PAdESDocTimeStampResult> CreateAsync(
        PAdESDocTimeStampRequest request,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        PdfSignaturePlaceholder placeholder = PdfIncrementalUpdateWriter.AppendPlaceholderDocTimeStamp(
            request.PriorDocument, request.Anchor, request.ContentsCapacityBytes, request.Filter);

        using DigestValue imprint = await ComputeByteRangeDigestAsync(
            placeholder, request.MessageImprintAlgorithm, pool, cancellationToken).ConfigureAwait(false);

        using AcquiredTimestampToken token = await TimestampAcquisition.AcquireAsync(
            imprint, request.TsaUri, request.FetchResponse, pool,
            request.ReqPolicyOid, request.NonceByteLength, request.IncludeNonce, cancellationToken).ConfigureAwait(false);

        return new PAdESDocTimeStampResult
        {
            Bytes = PdfIncrementalUpdateWriter.CompleteSignature(placeholder, token.Token.AsReadOnlyMemory()),
            ByteRange = placeholder.ByteRange,
            XrefOffset = placeholder.XrefOffset,
            DocTimeStampObjectNumber = placeholder.SignatureObjectNumber
        };
    }


    /// <summary>Computes the digest of a placeholder's own <c>ByteRange</c>-gapped bytes — the same computation <see cref="PAdESSignatureCreation"/> performs for an ordinary signature's own detached content.</summary>
    private static async ValueTask<DigestValue> ComputeByteRangeDigestAsync(
        PdfSignaturePlaceholder placeholder, PkiDigestAlgorithm algorithm, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        ReadOnlyMemory<byte> document = placeholder.Document;
        int firstLength = placeholder.ByteRange.FirstLength;
        int secondOffset = placeholder.ByteRange.SecondOffset;
        int secondLength = placeholder.ByteRange.SecondLength;
        int total = firstLength + secondLength;

        using IMemoryOwner<byte> concatenation = pool.Rent(total);
        document[..firstLength].CopyTo(concatenation.Memory);
        document.Slice(secondOffset, secondLength).CopyTo(concatenation.Memory[firstLength..]);

        return await CryptographicKeyEvents.ComputeDigestAsync(
            concatenation.Memory[..total], algorithm.OutputByteLength, algorithm.DigestTag, pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }
}
