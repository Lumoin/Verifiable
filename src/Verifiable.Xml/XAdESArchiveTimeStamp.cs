using System.Collections.Generic;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// The <c>ArchiveTimeStamp</c> qualifying property defined in the namespace whose URI is
/// <see cref="XAdESIdentifiers.XAdESNamespaceV141"/> (clause 5.5.2.1): an unsigned qualifying property that
/// qualifies the signature, of the shared <see cref="XAdESTimeStamp"/> (<c>XAdESTimeStampType</c>) shape —
/// "shall encapsulate electronic time-stamps computed on all the data objects incorporated into the XAdES
/// signature at the time of generating each electronic time-stamp." Unlike <see cref="XAdESSignatureTimeStamp"/>
/// and <see cref="XAdESAllDataObjectsTimeStamp"/>, this reader imposes NO Implicit-mechanism lock: clause
/// 5.5.2.3's not-distributed case uses the Implicit mechanism (no <c>Include</c>) while clause 5.5.2.4's
/// distributed case uses the Explicit mechanism (one <c>Include</c> per time-stamped unsigned qualifying
/// property, clause 5.5.2.2 step 6) — BOTH are legitimate incorporation shapes for this property, so
/// <see cref="XAdESTimeStamp.Includes"/> being empty or non-empty is read-time information the message-imprint
/// engine (<see cref="XAdESArchiveTimeStampImprint"/>) dispatches on, never a read-time refusal. The
/// v1.3.2-namespace <c>ArchiveTimeStamp</c> is a DIFFERENT, deprecated element (Annex D) already refused by name
/// in <see cref="XAdESUnsignedSignatureProperties.TryRead"/>; this type's own identity check is scoped to the
/// v1.4.1 namespace exclusively — the spec itself never names this property bare, always "<c>ArchiveTimeStamp</c>
/// defined in the namespace whose URI is [v1.4.1]," precisely because the deprecated v1.3.2 form also exists.
/// </summary>
/// <remarks>
/// <para>
/// Owns the pooled content any <c>EncapsulatedTimeStamp</c> entry decodes, so — like
/// <see cref="XAdESSignatureTimeStamp"/> — it is itself <see cref="IDisposable"/>, since
/// <see cref="XAdESTimeStamp.TryRead"/> takes a caller-supplied custody list rather than owning one itself.
/// </para>
/// <para>
/// Clause 5.5.2.1's <c>CounterSignature</c>/validation-material interaction rules and clause 5.5.2.2's
/// six-step generation procedure are GENERATION-side obligations, recorded here rather than implemented (this
/// leaf's own scope is verification):
/// </para>
/// <list type="bullet">
/// <item>(shall, conditional) "if the XAdES signature incorporates a <c>CounterSignature</c> unsigned
/// qualifying property, all the material required for validating the counter-signature shall be incorporated
/// [...] before generating the first <c>ArchiveTimeStamp</c>" — either within the counter-signature itself or
/// within the countersigned signature's own containers.</item>
/// <item>(should not) "the content of the <c>CounterSignature</c> property should not be changed once
/// time-stamped by an <c>ArchiveTimeStamp</c>" — NOTE 2 explains why: a later change would make the
/// <c>ArchiveTimeStamp</c> (and consequently the countersigned signature) fail validation; NOTE 3 names clause
/// 5.2.7.1's detached counter-signature mechanism as the escape hatch when a change is genuinely needed.</item>
/// <item>(shall, six numbered steps) clause 5.5.2.2's generation procedure: 1) add any missing certificates/
/// revocation data clause 5.4 properties would carry, before generating the time-stamp(s); 2) decide
/// not-distributed vs distributed by whether the new <c>ArchiveTimeStamp</c>'s PLANNED incorporation point will
/// share a parent with every property it time-stamps; 3) request the time-stamp(s) from the TSA(s); 4) build the
/// new <c>ArchiveTimeStamp</c> encapsulating them; 5) incorporate it as a new unsigned qualifying property;
/// 6) if, after incorporation, the distributed case turns out to apply, incorporate one <c>Include</c> per
/// time-stamped property, in the SAME order used to build the message-imprint input — the order
/// <see cref="XAdESArchiveTimeStampImprint.TryComputeDistributedImprintInput"/>'s validation-side counterpart
/// consumes.</item>
/// </list>
/// </remarks>
public sealed class XAdESArchiveTimeStamp: IDisposable
{
    /// <summary>The document the property was read from. Not owned; the caller disposes it separately.</summary>
    public XmlNodeTable Table { get; }

    /// <summary>The <c>ArchiveTimeStamp</c> element's own index.</summary>
    public int ElementIndex { get; }

    /// <summary>
    /// The read <c>XAdESTimeStampType</c> content. <see cref="XAdESTimeStamp.Includes"/> being empty selects the
    /// not-distributed message-imprint variant (clause 5.5.2.3); non-empty selects the distributed variant
    /// (clause 5.5.2.4) — see <see cref="XAdESArchiveTimeStampImprint"/>.
    /// </summary>
    public XAdESTimeStamp TimeStamp { get; }

    private List<PooledMemory> OwnedContent { get; }

    private bool isDisposed;


    private XAdESArchiveTimeStamp(XmlNodeTable table, int elementIndex, XAdESTimeStamp timeStamp, List<PooledMemory> ownedContent)
    {
        Table = table;
        ElementIndex = elementIndex;
        TimeStamp = timeStamp;
        OwnedContent = ownedContent;
    }


    /// <summary>
    /// Reads an <c>ArchiveTimeStamp</c> element through the shared <see cref="XAdESTimeStamp"/> grammar, after
    /// verifying the element's own identity is the v1.4.1-namespace form — the v1.3.2-namespace deprecated
    /// element is a different, unrelated element this type never accepts, even though
    /// <see cref="XAdESUnsignedSignatureProperties.TryRead"/> already refuses it by name one layer up whenever
    /// this reader is reached through that container's own dispatch.
    /// </summary>
    /// <param name="table">The node table.</param>
    /// <param name="elementIndex">The <c>ArchiveTimeStamp</c> element — typically obtained from an
    /// <see cref="XAdESUnsignedSignaturePropertyEntry"/> whose
    /// <see cref="XAdESUnsignedSignaturePropertyEntry.Name"/> is
    /// <see cref="XAdESUnsignedSignaturePropertyName.Unrecognized"/> and whose element identity is separately
    /// confirmed to be this v1.4.1-namespace element.</param>
    /// <param name="pool">The pool every decoded field is rented from.</param>
    /// <param name="value">The read model on success; the caller owns and must dispose it.</param>
    /// <param name="error">The refusal on failure:
    /// <see cref="XAdESReadFailure.UnknownCoreElement"/> when the element is not the v1.4.1-namespace
    /// <c>ArchiveTimeStamp</c>; every <see cref="XAdESTimeStamp.TryRead"/> refusal otherwise.</param>
    /// <returns><see langword="true"/> when the element was read.</returns>
    public static bool TryRead(XmlNodeTable table, int elementIndex, BaseMemoryPool pool, out XAdESArchiveTimeStamp? value, out XAdESReadError error)
    {
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(pool);
        value = null;
        if(!XmlSignatureModelGrammar.IsElement(table, elementIndex, XAdESIdentifiers.XAdESNamespaceV141Utf8, "ArchiveTimeStamp"u8))
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

            value = new XAdESArchiveTimeStamp(table, elementIndex, timeStamp, owned);
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
