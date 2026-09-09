using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// List of TPM handles (TPML_HANDLE).
/// </summary>
/// <remarks>
/// <para>
/// Returned by <c>TPM2_GetCapability()</c> when <c>capability == TPM_CAP_HANDLES</c> — the loaded, persistent,
/// or NV Index handles the query selected.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                            // Number of handles; may be 0.
///     TPM_HANDLE handle[count];                // The handles.
/// } TPML_HANDLE;
/// </code>
/// <para>
/// Part 2, Table 125 bounds <c>count</c> by the implementation-dependent <c>MAX_CAP_HANDLES</c>
/// (<c>= MAX_CAP_DATA / sizeof(TPM_HANDLE)</c>) and names <c>TPM_RC_SIZE</c> as the response when it is
/// exceeded. This carrier holds no pooled memory — each element is a 4-octet value type — so the bound
/// enforced here is the buffer-capacity guard <see cref="TpmReader.EnsureCount"/> already applies to
/// <see cref="TpmlDigest"/>: a count that could not possibly fit in the remaining wire bytes is refused before
/// it can size an allocation.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.8.4, Table 125.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlHandle: ITpmWireType
{
    private static TpmlHandle EmptyInstance { get; } = new(ImmutableArray<TpmHandle>.Empty);

    /// <summary>
    /// Initializes a new handle list.
    /// </summary>
    /// <param name="handles">The handles.</param>
    private TpmlHandle(ImmutableArray<TpmHandle> handles)
    {
        Handles = handles;
    }

    /// <summary>
    /// Gets an empty handle list.
    /// </summary>
    public static TpmlHandle Empty => EmptyInstance;

    /// <summary>
    /// Gets the handles.
    /// </summary>
    public ImmutableArray<TpmHandle> Handles { get; }

    /// <summary>
    /// Gets the number of handles.
    /// </summary>
    public int Count => Handles.Length;

    /// <summary>
    /// Gets whether this list is empty.
    /// </summary>
    public bool IsEmpty => Handles.Length == 0;

    /// <summary>
    /// Gets the handle at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The handle.</returns>
    public TpmHandle this[int index] => Handles[index];

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(uint) + (Handles.Length * sizeof(uint));

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)Handles.Length);

        foreach(TpmHandle handle in Handles)
        {
            handle.WriteTo(ref writer);
        }
    }

    /// <summary>
    /// Parses a handle list from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed handle list.</returns>
    /// <exception cref="InvalidOperationException">The count exceeds what the remaining buffer can hold (<c>TPM_RC_SIZE</c>).</exception>
    public static TpmlHandle Parse(ref TpmReader reader)
    {
        uint count = reader.ReadUInt32();

        if(count == 0)
        {
            return Empty;
        }

        //Each handle occupies 4 octets on the wire, so a count larger than the remaining buffer can hold is a
        //malformed length and must not size the backing array (Part 2, clause 10.8.4).
        reader.EnsureCount(count, sizeof(uint));

        var builder = ImmutableArray.CreateBuilder<TpmHandle>((int)count);
        for(int i = 0; i < count; i++)
        {
            builder.Add(TpmHandle.Parse(ref reader));
        }

        return new TpmlHandle(builder.MoveToImmutable());
    }

    private string DebuggerDisplay => $"TPML_HANDLE({Handles.Length} handles)";
}
