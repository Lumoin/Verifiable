namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// The <c>IssuerSigned</c> structure per ISO/IEC 18013-5 §8.3.2.1.2 — the
/// issuer-half of a signed mdoc document: the per-namespace claim items
/// plus the COSE_Sign1 carrying the Mobile Security Object (MSO).
/// </summary>
/// <remarks>
/// <para>
/// <see cref="NameSpaces"/> is the <c>IssuerNameSpaces</c> map: each namespace
/// (e.g. <c>org.iso.18013.5.1</c>, <c>org.iso.18013.5.1.aamva</c>) maps to an
/// ordered list of <see cref="MdocIssuerSignedItem"/> records. The list
/// ordering matches the issuer's authored ordering because the MSO digest
/// commitments key on each item's wire bytes, which depend on map insertion
/// order in the encoded namespaces map.
/// </para>
/// <para>
/// <see cref="IssuerAuth"/> carries the parsed MSO plus its original
/// COSE_Sign1 wire bytes (<see cref="MdocIssuerAuth"/>). It is non-nullable
/// because ISO/IEC 18013-5's CDDL for IssuerSigned requires both
/// nameSpaces and issuerAuth — anything typed as <see cref="MdocIssuerSigned"/>
/// is in its signed / wire-valid form. The pre-signing build-scaffold
/// counterpart is <see cref="MdocLogicalIssuerSigned"/>.
/// </para>
/// <para>
/// Disposal cascades into every item under every namespace, releasing each
/// item's <see cref="MdocIssuerSignedItem.Random"/> salt, and into
/// <see cref="IssuerAuth"/> to release its COSE_Sign1 wire-bytes carrier.
/// </para>
/// </remarks>
public sealed class MdocIssuerSigned: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a signed issuer-signed structure from caller-supplied
    /// namespaces and <c>issuerAuth</c>. Ownership of the items under
    /// <paramref name="nameSpaces"/> transfers to the new instance.
    /// </summary>
    public MdocIssuerSigned(
        IReadOnlyDictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces,
        MdocIssuerAuth issuerAuth)
    {
        ArgumentNullException.ThrowIfNull(nameSpaces);
        ArgumentNullException.ThrowIfNull(issuerAuth);

        NameSpaces = nameSpaces;
        IssuerAuth = issuerAuth;
    }


    /// <summary>
    /// The <c>IssuerNameSpaces</c> map. Each namespace string maps to a
    /// non-empty ordered list of <see cref="MdocIssuerSignedItem"/> records;
    /// each item carries the issuer's authored value plus the salt and digest
    /// identifier the MSO commits to.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<MdocIssuerSignedItem>> NameSpaces { get; }

    /// <summary>
    /// The parsed MSO + COSE_Sign1 wire bytes carrying the issuer signature.
    /// Required by ISO/IEC 18013-5 §8.3.2.1.2; non-nullable here so the
    /// type system carries that invariant.
    /// </summary>
    public MdocIssuerAuth IssuerAuth { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        foreach(IReadOnlyList<MdocIssuerSignedItem> items in NameSpaces.Values)
        {
            foreach(MdocIssuerSignedItem item in items)
            {
                item.Dispose();
            }
        }

        IssuerAuth.Dispose();
        disposed = true;
    }
}
