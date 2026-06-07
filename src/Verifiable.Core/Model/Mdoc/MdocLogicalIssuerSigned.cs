namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Logical (pre-signing) counterpart to <see cref="MdocIssuerSigned"/> —
/// the namespaced claim items the issuer has assembled but not yet
/// committed to via the COSE_Sign1 MSO.
/// </summary>
/// <remarks>
/// <para>
/// Carries only the <see cref="NameSpaces"/> map; the signed side's
/// <see cref="MdocIssuerSigned.IssuerAuth"/> has no analogue here because
/// the MSO is produced by the signing step. The type system thereby
/// prevents an unsigned shape from reaching any wire-emitting path.
/// </para>
/// <para>
/// Disposal cascades into every item under every namespace. After a
/// successful <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance.SignAsync"/>
/// call, the caller must not dispose this shape — the items' salts have
/// transferred to the signed side.
/// </para>
/// </remarks>
public sealed class MdocLogicalIssuerSigned: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a logical issuer-signed structure from caller-supplied
    /// namespaces. Ownership of the items transfers to the new instance.
    /// </summary>
    public MdocLogicalIssuerSigned(
        IReadOnlyDictionary<string, IReadOnlyList<MdocLogicalIssuerSignedItem>> nameSpaces)
    {
        ArgumentNullException.ThrowIfNull(nameSpaces);

        NameSpaces = nameSpaces;
    }


    /// <summary>
    /// The <c>IssuerNameSpaces</c> map in its pre-signing form. Each
    /// namespace maps to an ordered list of
    /// <see cref="MdocLogicalIssuerSignedItem"/> records; per-namespace
    /// ordering is preserved into the signed shape because the MSO digest
    /// commitments key on each item's wire bytes, which depend on map
    /// insertion order.
    /// </summary>
    public IReadOnlyDictionary<string, IReadOnlyList<MdocLogicalIssuerSignedItem>> NameSpaces { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        foreach(IReadOnlyList<MdocLogicalIssuerSignedItem> items in NameSpaces.Values)
        {
            foreach(MdocLogicalIssuerSignedItem item in items)
            {
                item.Dispose();
            }
        }

        disposed = true;
    }
}
