using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>AllDataObjectsTimeStamp</c> qualifying property of clause 5.2.8.1: a signed qualifying property
/// that qualifies signed data objects, of the shared <see cref="XAdESTimeStamp"/> (<c>XAdESTimeStampType</c>)
/// shape, hard-locked to the Implicit incorporation mechanism — "The Implicit mechanism (see clause 5.1.4.4.1)
/// shall be used for generating this qualifying property." Clause 5.1.4.4.1 defines the Implicit/Explicit
/// dichotomy structurally, not just by name: "Explicit. This mechanism shall use the <c>Include</c> element
/// for referencing specific data objects..."; "Implicit. For certain time-stamp container qualifying
/// properties under certain circumstances, no explicit indications are required..." — <c>Include</c> is the
/// Explicit mechanism's own exclusive marker, so an <c>AllDataObjectsTimeStamp</c> instance carrying ANY
/// <c>Include</c> element would mean the Explicit mechanism was actually used, directly contradicting the
/// Implicit-mechanism requirement clause 5.2.8.1 imposes; this reader adjudicates Include-presence as a read
/// refusal accordingly. The message-imprint computation itself (clause 5.2.8.1's numbered 1)-2) procedure,
/// concatenating every <c>ds:SignedInfo</c> reference except the <c>SignedProperties</c> one) is NOT built
/// here — it is <see cref="XAdESAllDataObjectsTimeStampImprint"/>'s own job.
/// </summary>
/// <remarks>
/// Owns the pooled content any <c>EncapsulatedTimeStamp</c> entry decodes, so — like
/// <see cref="XAdESSigningCertificateV2"/> — it is itself <see cref="IDisposable"/>, since
/// <see cref="XAdESTimeStamp.TryRead"/> takes a caller-supplied custody list rather than owning one itself.
/// </remarks>
public sealed class XAdESAllDataObjectsTimeStamp: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>AllDataObjectsTimeStamp</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The read <c>XAdESTimeStampType</c> content; <see cref="XAdESTimeStamp.Includes"/> is always empty (the Implicit-mechanism lock this type enforces).</summary>
    public XAdESTimeStamp TimeStamp { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESAllDataObjectsTimeStamp(XmlNodeTable table, int elementIndex, XAdESTimeStamp timeStamp, List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        TimeStamp = timeStamp;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads an <c>AllDataObjectsTimeStamp</c> element through the shared <see cref="XAdESTimeStamp"/> grammar,
    /// refusing any instance that carries at least one <c>Include</c> element.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>AllDataObjectsTimeStamp</c> element — typically obtained from a
    /// <see cref="XAdESSignedDataObjectPropertyEntry"/> whose
    /// <see cref="XAdESSignedDataObjectPropertyEntry.Name"/> is
    /// <see cref="XAdESSignedDataObjectPropertyName.AllDataObjectsTimeStamp"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure — every <see cref="XAdESTimeStamp.TryRead"/> refusal, or
    /// <see cref="XAdESReadFailure.AllDataObjectsTimeStampIncludeNotPermitted"/> when at least one
    /// <c>Include</c> element is present (clause 5.2.8.1's Implicit-mechanism lock).</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESAllDataObjectsTimeStamp? value, out XAdESReadError error)
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

            if(timeStamp.Includes.Count > 0)
            {
                error = new XAdESReadError(XAdESReadFailure.AllDataObjectsTimeStampIncludeNotPermitted, 0);

                return false;
            }

            value = new XAdESAllDataObjectsTimeStamp(table, elementIndex, timeStamp, owned);
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
