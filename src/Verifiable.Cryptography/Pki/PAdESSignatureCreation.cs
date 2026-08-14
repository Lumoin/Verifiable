using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What one <see cref="CAdESSignatureAugmentation.AddSignatureTimestampAsync"/> call inside
/// <see cref="PAdESSignatureCreation.SignAsync"/> needs to raise the produced signature to PAdES-B-T (ETSI EN
/// 319 142-1 Table 1, PA-6.3-T23/T24/n): the imprint algorithm and how to reach a Time-Stamping Authority. A
/// <see langword="null"/> <see cref="PAdESSigningRequest.SignatureTimestamp"/> produces PAdES-B-B alone.
/// </summary>
public sealed record PAdESSignatureTimestampRequest
{
    /// <summary>Gets the algorithm the message imprint is computed under, which the authority echoes in its token.</summary>
    public required PkiDigestAlgorithm MessageImprintAlgorithm { get; init; }

    /// <summary>Gets the Time-Stamping Authority to contact, in whatever form the transport delegate understands.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "Forwarded verbatim into CAdESSignatureTimestampContext.TsaUri, which is deliberately a string for the same reason that property gives: the transport delegate owns URI parsing and scheme policy.")]
    public required string TsaUri { get; init; }

    /// <summary>Gets the transport the request is sent through and the response read from.</summary>
    public required FetchTimestampResponseAsyncDelegate FetchResponse { get; init; }

    /// <summary>Gets the time-stamp policy the request asks for, or <see langword="null"/> to state none.</summary>
    public string? ReqPolicyOid { get; init; }

    /// <summary>Gets the nonce length in octets the request carries.</summary>
    public int NonceByteLength { get; init; } = 32;

    /// <summary>Gets whether the request carries a nonce.</summary>
    public bool IncludeNonce { get; init; } = true;

    /// <summary>Gets the instant the signing certificate is known to have been revoked, or <see langword="null"/> when none is known (Table 1 requirement m)'s check).</summary>
    public DateTimeOffset? SigningCertificateRevokedAt { get; init; }

    /// <summary>Gets whether the acquired token's generation time is checked against the signing certificate's validity window; see <see cref="CAdESSignatureTimestampContext.EnforceSigningCertificateValidity"/>.</summary>
    public bool EnforceSigningCertificateValidity { get; init; } = true;
}


/// <summary>
/// What one <see cref="PAdESSignatureCreation.SignAsync"/> call needs: the prior document revision the new
/// signature is layered on top of, the signer's identity, the Signature Dictionary field values, and — when
/// <see cref="SignatureTimestamp"/> is supplied — the Time-Stamping Authority that raises the result to
/// PAdES-B-T.
/// </summary>
public sealed record PAdESSigningRequest
{
    /// <summary>Gets the whole bytes of the revision the new signature is layered on top of.</summary>
    public required ReadOnlyMemory<byte> PriorDocument { get; init; }

    /// <summary>Gets where the prior revision's own cross-reference chain and catalog sit.</summary>
    public required PdfIncrementalUpdateAnchor Anchor { get; init; }

    /// <summary>Gets the number of raw signature bytes to reserve <c>Contents</c> capacity for; must fit the final CMS <c>SignedData</c> (larger for PAdES-B-T, whose token adds a <c>signature-time-stamp</c> unsigned attribute).</summary>
    public required int ContentsCapacityBytes { get; init; }

    /// <summary>Gets the signer's own certificate, placed first in <c>SignedData.certificates</c> (Table 1 requirement a) and hashed into the ESS <c>signing-certificate-v2</c> attribute.</summary>
    public required PkiCertificateMemory SignerCertificate { get; init; }

    /// <summary>Gets the signer's private key material; its tag resolves the signing delegate and the algorithm identities.</summary>
    public required PrivateKeyMemory SignerPrivateKey { get; init; }

    /// <summary>Gets the claimed UTC time written as the Signature Dictionary <c>M</c> entry (PA-6.3-T12/g).</summary>
    public required DateTimeOffset SigningTime { get; init; }

    /// <summary>Gets the digest algorithm the <c>ByteRange</c>-gapped bytes are hashed under and the CAdES signer's own message-digest algorithm.</summary>
    public PkiDigestAlgorithm MessageDigestAlgorithm { get; init; } = PkiDigestAlgorithm.Sha256;

    /// <summary>Gets the signature handler name written as the Signature Dictionary <c>Filter</c> entry.</summary>
    public string Filter { get; init; } = "Adobe.PPKLite";

    /// <summary>Gets the Signature Dictionary <c>Location</c> entry's text, or <see langword="null"/> to omit it.</summary>
    public string? Location { get; init; }

    /// <summary>
    /// Gets the Signature Dictionary <c>Reason</c> entry's text, or <see langword="null"/> to omit it. Table 1
    /// requirements m) forbid this alongside a <c>commitment-type-indication</c> or <c>signature-policy-identifier</c>
    /// signed attribute in <see cref="OptionalAttributes"/> — <see cref="PAdESSignatureCreation.SignAsync"/>
    /// refuses that combination fail-closed.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>Gets the Signature Dictionary <c>ContactInfo</c> entry's text, or <see langword="null"/> to omit it.</summary>
    public string? ContactInfo { get; init; }

    /// <summary>Gets the Signature Dictionary <c>Name</c> entry's text, or <see langword="null"/> to omit it.</summary>
    public string? Name { get; init; }

    /// <summary>Gets further certificates for <c>SignedData.certificates</c> (chain, revocation-signer, TSA certificates — requirement d).</summary>
    public IReadOnlyList<PkiCertificateMemory>? AdditionalCertificates { get; init; }

    /// <summary>Gets a caller-supplied dated cryptographic-constraints table the message-digest algorithm is assessed against, or <see langword="null"/> to apply only the unconditional refusals; see <see cref="CAdESSignatureCreation.PrepareAsync"/>.</summary>
    public CryptographicConstraints? AlgorithmConstraints { get; init; }

    /// <summary>Gets the opt-in Table 1 CMS/CAdES signed-attribute set (clause 5.2, PA-5.2-01/02) — the nine attribute names Leg 1's clause 5.2 catalogues, all of them already carried by <see cref="CAdESOptionalSignedAttributes"/> (RP-3).</summary>
    public CAdESOptionalSignedAttributes? OptionalAttributes { get; init; }

    /// <summary>Gets the Time-Stamping Authority context that raises the produced signature to PAdES-B-T, or <see langword="null"/> to produce PAdES-B-B alone.</summary>
    public PAdESSignatureTimestampRequest? SignatureTimestamp { get; init; }
}


/// <summary>
/// The result of <see cref="PAdESSignatureCreation.SignAsync"/>: the whole signed PDF document's bytes and the
/// CAdES level actually reached.
/// </summary>
public sealed record PAdESSignedDocument
{
    /// <summary>Gets the whole signed PDF document's bytes.</summary>
    public required byte[] Bytes { get; init; }

    /// <summary>Gets the level reached: <see cref="AdESBaselineLevel.BB"/> (PAdES-B-B) or <see cref="AdESBaselineLevel.BT"/> (PAdES-B-T).</summary>
    public required AdESBaselineLevel Level { get; init; }
}


/// <summary>
/// Creates a PAdES-B-B or PAdES-B-T signature
/// (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf">
/// ETSI EN 319 142-1 V1.2.1</see>) by composing the shipped CAdES creation and augmentation surfaces (RP-3)
/// over the incremental-update byte surface <see cref="PdfIncrementalUpdateWriter"/> mints: the detached CMS
/// <c>SignedData</c> is computed over the placeholder's own <c>ByteRange</c>-gapped document bytes, embedded as
/// the <c>Contents</c> hexadecimal string (SubFilter <c>ETSI.CAdES.detached</c>, PA-6.3-l), and — when a
/// Time-Stamping Authority context is supplied — raised to B-T before embedding.
/// </summary>
/// <remarks>
/// <para>
/// <strong>No CMS <c>signing-time</c> attribute.</strong> PA-6.3-T13 gives the CMS <c>signing-time</c> attribute
/// cardinality <c>0</c> at every baseline level ("shall not be present") because ISO 32000-1's own <c>M</c> entry
/// already carries the claimed signing time (PA-6.3-T12/g) — PA-4.1-04's anti-redundancy rule resolved concretely
/// for PAdES. This surface always calls <see cref="CAdESSignatureCreation.SignAsync"/> with
/// <c>shouldIncludeSigningTimeAttribute: false</c>, an additive extension of that shipped surface (RP-3) rather than a
/// re-modeling of its attribute assembly.
/// </para>
/// <para>
/// <strong>Reason vs. commitment-type-indication/signature-policy-identifier.</strong> PA-6.3-d2/m1/m2 make the
/// Signature Dictionary <c>Reason</c> entry and those two signed attributes mutually exclusive; this surface
/// refuses the combination before touching the byte surface or any cryptographic seam.
/// </para>
/// <para>
/// <strong>B-T reuses the exact same digest.</strong> The <c>ByteRange</c>-gapped document bytes — and so their
/// digest — never change between the B-B and B-T postures for one signing operation: raising the level only
/// grows what sits inside the already-reserved <c>Contents</c> capacity (a <c>signature-time-stamp</c> unsigned
/// attribute, clause 5.3), never the document bytes the signature itself covers. Both postures therefore embed
/// into the very same <see cref="PdfSignaturePlaceholder"/>.
/// </para>
/// </remarks>
public static class PAdESSignatureCreation
{
    /// <summary>
    /// Creates a PAdES-B-B signature, or a PAdES-B-T signature when <see cref="PAdESSigningRequest.SignatureTimestamp"/> is supplied.
    /// </summary>
    /// <param name="request">The signing request.</param>
    /// <param name="pool">The memory pool every allocation this call performs is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The signed document and the level reached.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="request"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <see cref="PAdESSigningRequest.Reason"/> is supplied alongside a <c>commitment-type-indication</c> or
    /// <c>signature-policy-identifier</c> optional attribute (PA-6.3-m1/m2), or the placeholder writer or the
    /// composed CAdES surface refuses the request (see <see cref="PdfIncrementalUpdateWriter.AppendPlaceholderSignature"/>
    /// and <see cref="CAdESSignatureCreation.PrepareAsync"/>).
    /// </exception>
    /// <exception cref="NotSupportedException">When <see cref="PAdESSigningRequest.MessageDigestAlgorithm"/> is refused by <see cref="CAdESSignatureCreation.PrepareAsync"/>, or <see cref="PAdESSigningRequest.SignerPrivateKey"/>'s algorithm is unsupported.</exception>
    /// <exception cref="TimestampAcquisitionException">When <see cref="PAdESSigningRequest.SignatureTimestamp"/> is supplied and the authority could not be reached, or the token it returned does not verify.</exception>
    public static async ValueTask<PAdESSignedDocument> SignAsync(
        PAdESSigningRequest request,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();
        EnsureReasonNotRedundant(request);

        PdfSignaturePlaceholder placeholder = PdfIncrementalUpdateWriter.AppendPlaceholderSignature(
            request.PriorDocument,
            request.Anchor,
            new PdfSignatureFieldValues
            {
                Filter = request.Filter,
                SigningTime = request.SigningTime,
                Location = request.Location,
                Reason = request.Reason,
                ContactInfo = request.ContactInfo,
                Name = request.Name
            },
            request.ContentsCapacityBytes);

        using DigestValue contentDigest = await ComputeByteRangeDigestAsync(
            placeholder, request.MessageDigestAlgorithm, pool, cancellationToken).ConfigureAwait(false);

        using CmsSignedData baseline = await CAdESSignatureCreation.SignAsync(
            request.SignerCertificate,
            request.SignerPrivateKey,
            content: null,
            detachedContentDigest: contentDigest.AsReadOnlyMemory(),
            signingTime: request.SigningTime,
            additionalCertificates: request.AdditionalCertificates,
            algorithmConstraints: request.AlgorithmConstraints,
            includeCmsAlgorithmProtection: false,
            pool,
            cancellationToken: cancellationToken,
            optionalAttributes: request.OptionalAttributes,
            shouldIncludeSigningTimeAttribute: false).ConfigureAwait(false);

        if(request.SignatureTimestamp is not { } timestampRequest)
        {
            return new PAdESSignedDocument
            {
                Bytes = PdfIncrementalUpdateWriter.CompleteSignature(placeholder, baseline.AsReadOnlyMemory()),
                Level = AdESBaselineLevel.BB
            };
        }

        using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
            new CAdESSignatureTimestampContext
            {
                SignedData = baseline,
                SignerIndex = 0,
                MessageImprintAlgorithm = timestampRequest.MessageImprintAlgorithm,
                TsaUri = timestampRequest.TsaUri,
                FetchResponse = timestampRequest.FetchResponse,
                ReqPolicyOid = timestampRequest.ReqPolicyOid,
                NonceByteLength = timestampRequest.NonceByteLength,
                IncludeNonce = timestampRequest.IncludeNonce,
                SigningCertificate = request.SignerCertificate,
                SigningCertificateRevokedAt = timestampRequest.SigningCertificateRevokedAt,
                EnforceSigningCertificateValidity = timestampRequest.EnforceSigningCertificateValidity
            },
            pool,
            cancellationToken).ConfigureAwait(false);

        return new PAdESSignedDocument
        {
            Bytes = PdfIncrementalUpdateWriter.CompleteSignature(placeholder, timestamped.AsReadOnlyMemory()),
            Level = AdESBaselineLevel.BT
        };
    }


    /// <summary>Refuses a request naming both <see cref="PAdESSigningRequest.Reason"/> and a commitment-type-indication/signature-policy-identifier optional attribute (PA-6.3-m1/m2).</summary>
    private static void EnsureReasonNotRedundant(PAdESSigningRequest request)
    {
        if(request.Reason is null || request.OptionalAttributes is not { } optional)
        {
            return;
        }

        if(optional.CommitmentType is not null)
        {
            throw new ArgumentException(
                "The entry with the key Reason shall not be used when the commitment-type-indication attribute is present in the CMS signature (ETSI EN 319 142-1 clause 6.3, requirement m).",
                nameof(request));
        }

        if(optional.SignaturePolicyIdentifier is not null)
        {
            throw new ArgumentException(
                "The entry with the key Reason shall not be used if the signature-policy-identifier attribute is present in the CMS signature (ETSI EN 319 142-1 clause 6.3, requirement m).",
                nameof(request));
        }
    }


    /// <summary>Computes the digest of a placeholder's own <c>ByteRange</c>-gapped bytes: the two signed segments laid end to end, the detached content every PAdES signature commits to.</summary>
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
