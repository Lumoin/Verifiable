namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Logical (pre-signing) counterpart to <see cref="MdocDocument"/> — the
/// build scaffold produced by <see cref="MdocIssuance.BuildDocument"/> and
/// consumed by <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance.SignAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// ISO/IEC 18013-5 does not model an unsigned mdoc — its CDDL for
/// <c>IssuerSigned</c> requires both <c>nameSpaces</c> and <c>issuerAuth</c>.
/// This type therefore represents an implementation-only state with no
/// wire encoding. By keeping it structurally distinct from
/// <see cref="MdocDocument"/>, the type system prevents the unsigned shape
/// from reaching any encoder, verifier, or presentation path.
/// </para>
/// <para>
/// Disposal cascades through <see cref="IssuerSigned"/> into every item
/// under every namespace. After a successful
/// <see cref="Verifiable.Cbor.Mdoc.MdocCborIssuance.SignAsync"/>, the
/// caller must not dispose this document — the items' salts have
/// transferred to the resulting <see cref="MdocDocument"/>.
/// </para>
/// </remarks>
public sealed class MdocLogicalDocument: IDisposable
{
    private bool disposed;


    /// <summary>
    /// Initializes a logical document from caller-supplied parts. Ownership
    /// of <paramref name="issuerSigned"/> transfers to the new document.
    /// </summary>
    public MdocLogicalDocument(
        string docType,
        MdocLogicalIssuerSigned issuerSigned)
    {
        ArgumentException.ThrowIfNullOrEmpty(docType);
        ArgumentNullException.ThrowIfNull(issuerSigned);

        DocType = docType;
        IssuerSigned = issuerSigned;
    }


    /// <summary>The document type URI (e.g. <c>org.iso.18013.5.1.mDL</c>, <c>eu.europa.ec.eudi.pid.1</c>).</summary>
    public string DocType { get; }

    /// <summary>The pre-signing namespaced claim items.</summary>
    public MdocLogicalIssuerSigned IssuerSigned { get; }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        IssuerSigned.Dispose();
        disposed = true;
    }
}
