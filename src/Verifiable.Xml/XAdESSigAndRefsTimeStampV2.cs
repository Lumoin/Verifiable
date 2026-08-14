using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>SigAndRefsTimeStampV2</c> qualifying property defined in the namespace whose URI is
/// <see cref="XAdESIdentifiers.XAdESNamespaceV141"/> (clause A.1.5.1): an unsigned qualifying property that
/// qualifies the signature, of the shared <see cref="XAdESTimeStamp"/> (<c>xades:XAdESTimeStampType</c>) shape —
/// "shall encapsulate electronic time-stamps on the digital signature value, the signature time-stamp (if
/// present), and the XAdES qualifying properties containing references to validation data." Annex D item 6
/// prints the defining-clause citation as "clause A.1.3" (defect XP-4a, recorded, never propagated) — this
/// type's own doc comments and every anchor cite the TRUE defining clause, A.1.5.1. Like
/// <see cref="XAdESArchiveTimeStamp"/>, this reader imposes NO Implicit-mechanism lock: A.1.5.1.2's
/// not-distributed case uses the Implicit mechanism (no <c>Include</c>) while A.1.5.1.3's distributed case uses
/// the Explicit mechanism (one <c>Include</c> per time-stamped unsigned qualifying property) — BOTH are
/// legitimate incorporation shapes, so <see cref="XAdESTimeStamp.Includes"/> being empty or non-empty is
/// read-time information the message-imprint engine (<see cref="XAdESSigAndRefsTimeStampV2Imprint"/>) dispatches
/// on, never a read-time refusal.
/// </summary>
/// <remarks>
/// Owns the pooled content any <c>EncapsulatedTimeStamp</c> entry decodes, so — like
/// <see cref="XAdESArchiveTimeStamp"/> — it is itself <see cref="IDisposable"/>, since
/// <see cref="XAdESTimeStamp.TryRead"/> takes a caller-supplied custody list rather than owning one itself.
/// </remarks>
public sealed class XAdESSigAndRefsTimeStampV2: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>SigAndRefsTimeStampV2</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>
    /// The read <c>XAdESTimeStampType</c> content. <see cref="XAdESTimeStamp.Includes"/> being empty selects the
    /// not-distributed message-imprint variant (clause A.1.5.1.2); non-empty selects the distributed variant
    /// (clause A.1.5.1.3) — see <see cref="XAdESSigAndRefsTimeStampV2Imprint"/>.
    /// </summary>
    public XAdESTimeStamp TimeStamp { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESSigAndRefsTimeStampV2(XmlNodeTable table, int elementIndex, XAdESTimeStamp timeStamp, List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        TimeStamp = timeStamp;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>SigAndRefsTimeStampV2</c> element through the shared <see cref="XAdESTimeStamp"/> grammar,
    /// after verifying the element's own identity is the v1.4.1-namespace form.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SigAndRefsTimeStampV2</c> element — typically obtained from an
    /// <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/> and whose element identity is separately
    /// confirmed to be this v1.4.1-namespace element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.UnknownCoreElement"/> when the element is not the v1.4.1-namespace
    /// <c>SigAndRefsTimeStampV2</c>; every <see cref="XAdESTimeStamp.TryRead"/> refusal otherwise.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESSigAndRefsTimeStampV2? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV141Utf8, "SigAndRefsTimeStampV2"u8))
        {
            error = new XAdESReadError(XAdESReadFailure.UnknownCoreElement, 0);

            return false;
        }

        var owned = new List<PooledMemory>();
        try
        {
            if(!XAdESTimeStamp.TryRead(table, elementIndex, pool, owned, out XAdESTimeStamp timeStamp, out error))
            {
                return false;
            }

            value = new XAdESSigAndRefsTimeStampV2(table, elementIndex, timeStamp, owned);
            error = default;

            return true;
        }
        finally
        {
            if(value is null)
            {
                for(int i = 0; i < owned.Count; ++i)
                {
                    owned[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Tells whether this value was read over the given table instance — the identity guard this library
    /// requires before any processing that combines this value with another table-scoped argument.
    /// </summary>
    /// <param name="table">The table to check against.</param>
    /// <returns><see langword="true"/> when this value was read from the same table instance.</returns>
    public bool IsOver(XmlNodeTable table)
    {
        return ReferenceEquals(Table, table);
    }


    /// <summary>
    /// Releases every decoded field <see cref="TimeStamp"/> owns. <see cref="Table"/> is not owned and is not
    /// disposed here. Idempotent.
    /// </summary>
    public void Dispose()
    {
        if(isDisposed)
        {
            return;
        }

        isDisposed = true;
        for(int i = 0; i < OwnedContent.Count; ++i)
        {
            OwnedContent[i].Dispose();
        }
    }
}
