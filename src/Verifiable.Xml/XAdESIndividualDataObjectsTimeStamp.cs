using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>IndividualDataObjectsTimeStamp</c> qualifying property of clause 5.2.8.2: a signed qualifying
/// property that qualifies signed data objects, of the shared <see cref="XAdESTimeStamp"/>
/// (<c>XAdESTimeStampType</c>) shape, hard-locked to the Explicit (<c>Include</c>) incorporation mechanism —
/// "The explicit (<c>Include</c>) mechanism shall be used for generating this qualifying property," mirror
/// image of <see cref="XAdESAllDataObjectsTimeStamp"/>'s Implicit-mechanism lock. This reader enforces the
/// one structural rule clause 5.2.8.2 states about the <c>Include</c> elements themselves: "The
/// <c>referencedData</c> attribute shall be present in each and every <c>Include</c> element, and set to
/// <c>"true"</c>" — a mandatory-attribute-with-fixed-value constraint the shared <c>IncludeType</c> schema
/// (clause 5.1.4.4.2.1) leaves optional, so it is checked here at the application layer. The message-imprint
/// computation itself (clause 5.2.8.2's numbered 1)-2) procedure, over the <c>Include</c>-selected subset in
/// <c>Include</c> document order) is NOT built here — it is
/// <see cref="XAdESIndividualDataObjectsTimeStampImprint"/>'s own job.
/// </summary>
/// <remarks>
/// Owns the pooled content any <c>EncapsulatedTimeStamp</c> entry decodes, so — like
/// <see cref="XAdESSigningCertificateV2"/> — it is itself <see cref="IDisposable"/>, since
/// <see cref="XAdESTimeStamp.TryRead"/> takes a caller-supplied custody list rather than owning one itself.
/// </remarks>
public sealed class XAdESIndividualDataObjectsTimeStamp: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>IndividualDataObjectsTimeStamp</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The read <c>XAdESTimeStampType</c> content; every entry of <see cref="XAdESTimeStamp.Includes"/> carries <c>referencedData="true"</c> (the structural rule this type enforces).</summary>
    public XAdESTimeStamp TimeStamp { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESIndividualDataObjectsTimeStamp(XmlNodeTable table, int elementIndex, XAdESTimeStamp timeStamp, List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        TimeStamp = timeStamp;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads an <c>IndividualDataObjectsTimeStamp</c> element through the shared <see cref="XAdESTimeStamp"/>
    /// grammar, refusing any instance whose <c>Include</c> elements do not each carry
    /// <c>referencedData="true"</c>.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>IndividualDataObjectsTimeStamp</c> element — typically obtained from
    /// a <see cref="XAdESSignedDataObjectPropertyEntry"/> whose
    /// <see cref="XAdESSignedDataObjectPropertyEntry.Name"/> is
    /// <see cref="XAdESSignedDataObjectPropertyName.IndividualDataObjectsTimeStamp"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure — every <see cref="XAdESTimeStamp.TryRead"/> refusal, or
    /// <see cref="XAdESReadFailure.IndividualDataObjectsTimeStampIncludeReferencedDataNotTrue"/> when at
    /// least one <c>Include</c> element's <c>referencedData</c> attribute is absent or not the literal
    /// <c>"true"</c> (clause 5.2.8.2's "each and every" rule).</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESIndividualDataObjectsTimeStamp? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        var owned = new List<PooledMemory>();
        try
        {
            if(!XAdESTimeStamp.TryRead(table, elementIndex, pool, owned, out XAdESTimeStamp timeStamp, out error))
            {
                return false;
            }

            foreach(XAdESInclude include in timeStamp.Includes)
            {
                if(!include.HasReferencedData || !include.ReferencedData)
                {
                    error = new XAdESReadError(XAdESReadFailure.IndividualDataObjectsTimeStampIncludeReferencedDataNotTrue, 0);

                    return false;
                }
            }

            value = new XAdESIndividualDataObjectsTimeStamp(table, elementIndex, timeStamp, owned);
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
