using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// List of algorithm identifiers (TPML_ALG).
/// </summary>
/// <remarks>
/// <para>
/// Returned by <c>TPM2_IncrementalSelfTest()</c> to report the algorithms remaining to be tested.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                            // Number of algorithms; may be 0.
///     TPM_ALG_ID algorithms[count];             // The algorithm identifiers.
/// } TPML_ALG;
/// </code>
/// <para>
/// Part 2, Table 121 bounds an input <c>count</c> by the implementation-dependent <c>MAX_ALG_LIST_SIZE</c>
/// ("The maximum only applies to an algorithm list in a command. The response size is limited only by the
/// size of the parameter buffer") and names <c>TPM_RC_SIZE</c> as the response when it is exceeded. This
/// carrier holds no pooled memory — each element is a 2-octet value type — so the bound enforced here is the
/// buffer-capacity guard <see cref="TpmReader.EnsureCount"/> already applies to <see cref="TpmlDigest"/>: a
/// count that could not possibly fit in the remaining wire bytes is refused before it can size an allocation.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.9.3, Table 121.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlAlg: ITpmWireType
{
    private static TpmlAlg EmptyInstance { get; } = new(ImmutableArray<TpmAlgIdConstants>.Empty);

    /// <summary>
    /// Initializes a new algorithm list.
    /// </summary>
    /// <param name="algorithms">The algorithm identifiers.</param>
    private TpmlAlg(ImmutableArray<TpmAlgIdConstants> algorithms)
    {
        Algorithms = algorithms;
    }

    /// <summary>
    /// Gets an empty algorithm list.
    /// </summary>
    public static TpmlAlg Empty => EmptyInstance;

    /// <summary>
    /// Gets the algorithm identifiers.
    /// </summary>
    public ImmutableArray<TpmAlgIdConstants> Algorithms { get; }

    /// <summary>
    /// Gets the number of algorithm identifiers.
    /// </summary>
    public int Count => Algorithms.Length;

    /// <summary>
    /// Gets whether this list is empty.
    /// </summary>
    public bool IsEmpty => Algorithms.Length == 0;

    /// <summary>
    /// Gets the algorithm identifier at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The algorithm identifier.</returns>
    public TpmAlgIdConstants this[int index] => Algorithms[index];

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(uint) + (Algorithms.Length * sizeof(ushort));

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)Algorithms.Length);

        foreach(TpmAlgIdConstants algorithm in Algorithms)
        {
            writer.WriteUInt16((ushort)algorithm);
        }
    }

    /// <summary>
    /// Parses an algorithm list from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed algorithm list.</returns>
    /// <exception cref="InvalidOperationException">The count exceeds what the remaining buffer can hold (<c>TPM_RC_SIZE</c>).</exception>
    public static TpmlAlg Parse(ref TpmReader reader)
    {
        uint count = reader.ReadUInt32();

        if(count == 0)
        {
            return Empty;
        }

        //Each algorithm identifier occupies 2 octets on the wire, so a count larger than the remaining buffer
        //can hold is a malformed length and must not size the backing array (Part 2, §10.9.3).
        reader.EnsureCount(count, sizeof(ushort));

        var builder = ImmutableArray.CreateBuilder<TpmAlgIdConstants>((int)count);
        for(int i = 0; i < count; i++)
        {
            builder.Add((TpmAlgIdConstants)reader.ReadUInt16());
        }

        return new TpmlAlg(builder.MoveToImmutable());
    }

    private string DebuggerDisplay => $"TPML_ALG({Algorithms.Length} algorithms)";
}
