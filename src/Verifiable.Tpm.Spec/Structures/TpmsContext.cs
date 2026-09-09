using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// The metadata and opaque blob exchanged by <c>TPM2_ContextSave()</c> and <c>TPM2_ContextLoad()</c>
/// (TPMS_CONTEXT).
/// </summary>
/// <remarks>
/// <para>
/// "This structure is used in TPM2_ContextLoad() and TPM2_ContextSave(). If the values of the TPMS_CONTEXT
/// Structure in TPM2_ContextLoad() are not the same as the values when the context was saved
/// (TPM2_ContextSave()), then the TPM shall not load the context." (TPM 2.0 Library Part 2, clause 14.5). The
/// four fields form the round-trip carrier a caller stores between a save and a later load; the simulator's own
/// parser reads the four steps separately so it can answer <c>TPM_RC_VALUE</c>, <c>TPM_RC_SIZE</c> and
/// <c>TPM_RC_INSUFFICIENT</c> apart rather than through this type's combined <see cref="Parse"/>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT64 sequence;                 // The sequence number of the context.
///     TPMI_DH_SAVED savedHandle;       // A handle indicating if the context is a session, object, or
///                                       // sequence object (see Table 58).
///     TPMI_RH_HIERARCHY+ hierarchy;    // The hierarchy of the context.
///     TPM2B_CONTEXT_DATA contextBlob;  // The context data and integrity HMAC.
/// } TPMS_CONTEXT;
/// </code>
/// <para>
/// <c>sequence</c>: "the sequence number of the context — Transient object contexts and session contexts used
/// different counters." <c>savedHandle</c>: "a handle indicating if the context is a session, object, or
/// sequence object (see Table 58)." <c>hierarchy</c>: "the hierarchy of the context." <c>contextBlob</c>: "the
/// context data and integrity HMAC." (TPM 2.0 Library Part 2, clause 14.5, Table 260.)
/// </para>
/// <para>
/// <c>hierarchy</c> carries Table 260's <c>+</c> admission — a saved session or sequence context is always in
/// the NULL hierarchy — which the existing <see cref="TpmiRhHierarchy"/> already satisfies as one of its four
/// ordinary admitted values; no separate NULL-admitting overload exists or is needed for this field.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 14.5, Table 260.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsContext: IDisposable
{
    /// <summary>
    /// Whether <see cref="Dispose"/> has already released <see cref="ContextBlob"/>.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Gets the sequence number of the context. Transient object contexts and session contexts are drawn from
    /// different counters (TPM 2.0 Library Part 2, clause 14.5, Table 260).
    /// </summary>
    public ulong Sequence { get; }

    /// <summary>
    /// Gets the handle indicating whether the context is a session, an object, or a sequence object (Table 58).
    /// </summary>
    public TpmiDhSaved SavedHandle { get; }

    /// <summary>
    /// Gets the hierarchy of the context.
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Gets the context data and integrity HMAC.
    /// </summary>
    /// <remarks>
    /// Ownership: OWNED. Disposed by <see cref="Dispose"/>.
    /// </remarks>
    public Tpm2bContextData ContextBlob { get; }

    /// <summary>
    /// Initializes context metadata over an owned blob.
    /// </summary>
    /// <param name="sequence">The sequence number of the context.</param>
    /// <param name="savedHandle">The handle indicating the kind of the saved resource.</param>
    /// <param name="hierarchy">The hierarchy of the context.</param>
    /// <param name="contextBlob">The context data and integrity HMAC. Ownership transfers to this instance.</param>
    public TpmsContext(ulong sequence, TpmiDhSaved savedHandle, TpmiRhHierarchy hierarchy, Tpm2bContextData contextBlob)
    {
        ArgumentNullException.ThrowIfNull(contextBlob);

        Sequence = sequence;
        SavedHandle = savedHandle;
        Hierarchy = hierarchy;
        ContextBlob = contextBlob;
    }

    /// <summary>
    /// Parses context metadata from a TPM reader.
    /// </summary>
    /// <remarks>
    /// Reads the four fields in wire order. Of the four, only <see cref="ContextBlob"/> rents pooled storage —
    /// <see cref="Sequence"/>, <see cref="SavedHandle"/> and <see cref="Hierarchy"/> are fixed-width value
    /// types that own nothing — so the dispose-on-throw ladder <see cref="TpmsCreationData.Parse"/> nests
    /// through five levels collapses here to a single site: nothing is rented before <see cref="Tpm2bContextData.Parse"/>
    /// is reached, and once it returns successfully there is no further field to fail on.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed context.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="reader"/>'s <c>savedHandle</c> or <c>hierarchy</c> is outside its admitted set, or <c>contextBlob</c> declares a size exceeding <see cref="Tpm2bContextData.MaxSize"/> (<c>TPM_RC_VALUE</c> / <c>TPM_RC_SIZE</c>).</exception>
    /// <exception cref="ArgumentOutOfRangeException"><c>contextBlob</c> declares a size exceeding the octets remaining in <paramref name="reader"/> (<c>TPM_RC_INSUFFICIENT</c>).</exception>
    public static TpmsContext Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ulong sequence = reader.ReadUInt64();
        TpmiDhSaved savedHandle = TpmiDhSaved.Parse(ref reader);
        TpmiRhHierarchy hierarchy = TpmiRhHierarchy.Parse(ref reader);
        Tpm2bContextData contextBlob = Tpm2bContextData.Parse(ref reader, pool);

        return new TpmsContext(sequence, savedHandle, hierarchy, contextBlob);
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt64(Sequence);
        SavedHandle.WriteTo(ref writer);
        Hierarchy.WriteTo(ref writer);
        ContextBlob.WriteTo(ref writer);
    }

    /// <summary>
    /// Gets the serialized size of this structure: the <c>UINT64</c> sequence, the two 4-octet handles, and the
    /// blob's own serialized size.
    /// </summary>
    public int SerializedSize => sizeof(ulong) + sizeof(uint) + sizeof(uint) + ContextBlob.SerializedSize;

    /// <summary>
    /// Releases <see cref="ContextBlob"/>.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            ContextBlob.Dispose();
            disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: <see cref="Sequence"/>, <see cref="SavedHandle"/>,
    /// <see cref="Hierarchy"/>, and <see cref="ContextBlob"/>'s octet count — never the blob's octets themselves.
    /// </summary>
    private string DebuggerDisplay => $"TPMS_CONTEXT(sequence={Sequence}, savedHandle=0x{SavedHandle.Value:X8}, hierarchy=0x{Hierarchy.Value:X8}, blob={ContextBlob.Size} bytes)";
}
