using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>SignatureTimeStamp</c> qualifying property of clause 5.3: an unsigned qualifying property that
/// qualifies the signature, of the shared <see cref="XAdESTimeStamp"/> (<c>XAdESTimeStampType</c>) shape,
/// hard-locked to the Implicit incorporation mechanism — "The Implicit mechanism (see clause 5.1.4.4.1) shall
/// be used for generating this qualifying property," the identical rule clause 5.2.8.1 states for
/// <see cref="XAdESAllDataObjectsTimeStamp"/> and adjudicated here the SAME way: clause 5.1.4.4.1 defines
/// <c>Include</c> as the Explicit mechanism's own exclusive marker ("Explicit. This mechanism shall use the
/// <c>Include</c> element for referencing specific data objects..."), so any <c>Include</c> element present on
/// a <c>SignatureTimeStamp</c> instance would mean the Explicit mechanism was actually used, directly
/// contradicting the Implicit-mechanism requirement — this reader refuses that shape at read time, mirroring
/// <see cref="XAdESAllDataObjectsTimeStamp.TryRead"/>'s own reasoning and structure exactly. The message-imprint
/// computation itself (clause 5.3's two-step "take the <c>ds:SignatureValue</c> element and its contents;
/// canonicalize it as specified in clause 4.5" procedure) is NOT built here — see
/// <see cref="XAdESSignatureTimeStampImprint"/>.
/// </summary>
/// <remarks>
/// Owns the pooled content any <c>EncapsulatedTimeStamp</c> entry decodes, so — like
/// <see cref="XAdESAllDataObjectsTimeStamp"/> — it is itself <see cref="IDisposable"/>, since
/// <see cref="XAdESTimeStamp.TryRead"/> takes a caller-supplied custody list rather than owning one itself.
/// </remarks>
public sealed class XAdESSignatureTimeStamp: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>SignatureTimeStamp</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>The read <c>XAdESTimeStampType</c> content; <see cref="XAdESTimeStamp.Includes"/> is always empty (the Implicit-mechanism lock this type enforces).</summary>
    public XAdESTimeStamp TimeStamp { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESSignatureTimeStamp(XmlNodeTable table, int elementIndex, XAdESTimeStamp timeStamp, List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        TimeStamp = timeStamp;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads a <c>SignatureTimeStamp</c> element through the shared <see cref="XAdESTimeStamp"/> grammar,
    /// refusing any instance that carries at least one <c>Include</c> element.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>SignatureTimeStamp</c> element — typically obtained from an
    /// <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.SignatureTimeStamp"/>.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure — every <see cref="XAdESTimeStamp.TryRead"/> refusal, or
    /// <see cref="XAdESReadFailure.SignatureTimeStampIncludeNotPermitted"/> when at least one <c>Include</c>
    /// element is present (clause 5.3's Implicit-mechanism lock).</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESSignatureTimeStamp? value, out XAdESReadError error)
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
                error = new XAdESReadError(XAdESReadFailure.SignatureTimeStampIncludeNotPermitted, 0);

                return false;
            }

            value = new XAdESSignatureTimeStamp(table, elementIndex, timeStamp, owned);
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
