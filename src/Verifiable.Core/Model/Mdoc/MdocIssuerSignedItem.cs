using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// One <c>IssuerSignedItem</c> entry per ISO/IEC 18013-5 §8.3.2.1.2.2 — the
/// quadruple (digestID, random, elementIdentifier, elementValue) that the
/// issuer commits to via the Mobile Security Object's <c>valueDigests</c> map,
/// plus the exact Tag-24-wrapped wire bytes the MSO digest commitment hashes.
/// </summary>
/// <remarks>
/// <para>
/// This type represents an item in its signed / wire-valid form — both
/// <see cref="WireBytes"/> and the enclosing
/// <see cref="MdocIssuerSigned.IssuerAuth"/> are populated. The pre-signing
/// build-scaffold counterpart is
/// <see cref="MdocLogicalIssuerSignedItem"/>; the split mirrors ISO/IEC
/// 18013-5's structural invariant that an IssuerSignedItem on the wire
/// always carries the bytes the MSO commits to.
/// </para>
/// <para>
/// <see cref="Random"/> is held as a <see cref="Salt"/> so the underlying
/// memory has a clear owner (this item) and a tag carrying provenance
/// (<see cref="CryptoTags.MdocIssuerSignedItemRandom"/>). Disposing the item
/// disposes the salt. The same pattern <see cref="Verifiable.JCose.Sd.SdDisclosure"/>
/// uses for its own salt ownership.
/// </para>
/// <para>
/// <see cref="EncodedElementValue"/> is a borrow — it points into a byte
/// buffer owned by the caller (issuance flow) or the decoder's source buffer
/// (parse flow). Element-specific decoding (CBOR tdate, full-date,
/// driving_privileges array, …) lives at the higher extractor layer.
/// </para>
/// <para>
/// <see cref="WireBytes"/> is a slice of the issuer's exact Tag-24-wrapped
/// bytes for this item. On the issuance path the
/// <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance.SignAsync"/> step fills
/// it; on the parse path the decoder fills it from the source buffer.
/// Verifiers hash these bytes verbatim against the MSO commitment.
/// </para>
/// </remarks>
public sealed class MdocIssuerSignedItem: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes an item from caller-supplied fields. Ownership of
    /// <paramref name="random"/> transfers to the new item; disposing the
    /// item disposes the salt.
    /// </summary>
    /// <param name="digestId">The digest identifier, unique within the enclosing namespace.</param>
    /// <param name="random">
    /// The per-item random salt (≥ <see cref="MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength"/>
    /// bytes per §9.1.2.5). Ownership transfers to the new item.
    /// </param>
    /// <param name="elementIdentifier">The claim name within the enclosing namespace.</param>
    /// <param name="encodedElementValue">The pre-encoded element value bytes.</param>
    /// <param name="wireBytes">
    /// The Tag-24-wrapped wire bytes for this item. Filled by the encoder
    /// on the issue path and by the decoder on the parse path; the MSO
    /// digest commitment hashes these bytes verbatim.
    /// </param>
    public MdocIssuerSignedItem(
        uint digestId,
        Salt random,
        string elementIdentifier,
        ReadOnlyMemory<byte> encodedElementValue,
        ReadOnlyMemory<byte> wireBytes)
    {
        ArgumentNullException.ThrowIfNull(random);
        ArgumentException.ThrowIfNullOrEmpty(elementIdentifier);

        DigestId = digestId;
        Random = random;
        ElementIdentifier = elementIdentifier;
        EncodedElementValue = encodedElementValue;
        WireBytes = wireBytes;
    }


    /// <summary>
    /// The digest identifier, unique within the enclosing namespace. The MSO's
    /// <c>valueDigests[namespace][digestID]</c> entry commits to the
    /// SHA-256/384/512 of this item's wire bytes.
    /// </summary>
    public uint DigestId { get; }

    /// <summary>
    /// The per-item random salt. Owned by this item; the caller reads
    /// <see cref="Salt.AsReadOnlySpan"/> when it needs the bytes and must not
    /// dispose the salt independently.
    /// </summary>
    public Salt Random { get; }

    /// <summary>
    /// The element identifier within the enclosing namespace (e.g.
    /// <c>family_name</c>, <c>birth_date</c>, <c>age_over_18</c>).
    /// </summary>
    public string ElementIdentifier { get; }

    /// <summary>
    /// The raw encoding of the element value. Higher layers decode per
    /// element-identifier semantics (tdate, full-date, tstr, bool, etc.).
    /// </summary>
    public ReadOnlyMemory<byte> EncodedElementValue { get; }

    /// <summary>
    /// The issuer's exact Tag-24-wrapped wire bytes for this item. Verifiers
    /// that compute the MSO digest commitment hash these bytes verbatim.
    /// </summary>
    public ReadOnlyMemory<byte> WireBytes { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        Random.Dispose();
        disposed = true;
    }
}
