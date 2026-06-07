using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Logical (pre-signing) counterpart to <see cref="MdocIssuerSignedItem"/> —
/// an <c>IssuerSignedItem</c> in its build-scaffold form, before the CBOR
/// encoder has produced the Tag-24 wire bytes that the MSO commits to.
/// </summary>
/// <remarks>
/// <para>
/// ISO/IEC 18013-5 §8.3.2.1.2.2 defines an IssuerSignedItem as the
/// (digestID, random, elementIdentifier, elementValue) quadruple. The
/// standard has no notion of an "unsigned IssuerSignedItem" — the wire
/// shape always carries the bytes the MSO commits to. This type represents
/// the implementation-side construction state between
/// <see cref="MdocIssuance.BuildDocument"/> and
/// <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance.SignAsync"/>, where the
/// claim data is assembled but the Tag-24 wrapping hasn't happened yet.
/// </para>
/// <para>
/// The logical type carries no <see cref="MdocIssuerSignedItem.WireBytes"/>
/// slot and no <see cref="MdocIssuerSigned.IssuerAuth"/> sibling — both are
/// produced by the signing step. By construction, a logical item cannot be
/// mistaken for a wire-valid item; the type system carries the invariant
/// the runtime guards today via defensive checks.
/// </para>
/// <para>
/// <see cref="Random"/> ownership: the logical item owns its salt until the
/// signing step. <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance.SignAsync"/>
/// transfers ownership to the freshly-constructed
/// <see cref="MdocIssuerSignedItem"/> on the signed side; the caller must
/// not dispose the logical item (or the enclosing
/// <see cref="MdocLogicalDocument"/>) after a successful signing call.
/// </para>
/// </remarks>
public sealed class MdocLogicalIssuerSignedItem: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a logical item from caller-supplied fields. Ownership of
    /// <paramref name="random"/> transfers to the new item.
    /// </summary>
    /// <param name="digestId">The digest identifier, unique within the enclosing namespace.</param>
    /// <param name="random">
    /// The per-item random salt (≥ <see cref="MdocWellKnownKeys.IssuerSignedItemRandomMinimumLength"/>
    /// bytes per §9.1.2.5). Ownership transfers to the new item.
    /// </param>
    /// <param name="elementIdentifier">The claim name within the enclosing namespace.</param>
    /// <param name="encodedElementValue">The pre-encoded element value bytes.</param>
    public MdocLogicalIssuerSignedItem(
        uint digestId,
        Salt random,
        string elementIdentifier,
        ReadOnlyMemory<byte> encodedElementValue)
    {
        ArgumentNullException.ThrowIfNull(random);
        ArgumentException.ThrowIfNullOrEmpty(elementIdentifier);

        DigestId = digestId;
        Random = random;
        ElementIdentifier = elementIdentifier;
        EncodedElementValue = encodedElementValue;
    }


    /// <summary>The digest identifier, unique within the enclosing namespace.</summary>
    public uint DigestId { get; }

    /// <summary>
    /// The per-item random salt. Owned by this item until the signing step
    /// transfers ownership to the <see cref="MdocIssuerSignedItem"/> on the
    /// signed side.
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
