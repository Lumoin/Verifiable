using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Attributes;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// List of command attributes (TPML_CCA).
/// </summary>
/// <remarks>
/// <para>
/// "This Table 123 list is only used in TPM2_GetCapability(capability == TPM_CAP_COMMANDS)" — it is the
/// <c>command</c> member of <c>TPMU_CAPABILITIES</c> (Part 2, clause 10.9.1, Table 138). Its elements are
/// <c>TPMA_CC</c> attribute words, not bare <c>TPM_CC</c> command codes: the command code rides in the low
/// 16 bits as <c>commandIndex</c> and the remaining bits carry the resource attributes a TPM Resource Manager
/// needs. The sibling <c>TPML_CC</c> carries bare command codes and is what
/// <c>TPM_CAP_PP_COMMANDS</c>/<c>TPM_CAP_AUDIT_COMMANDS</c> return.
/// </para>
/// <para>
/// "The values in the list are returned in TPMA_CC-&gt;commandIndex order … with vendor-specific commands
/// returned after other commands. Because of the other attributes, the commands may not be returned in strict
/// numerical order."
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                            // Number of values; may be 0.
///     TPMA_CC commandAttributes[count];        // The command attributes.
/// } TPML_CCA;
/// </code>
/// <para>
/// Table 123 bounds <c>count</c> by the implementation-dependent <c>MAX_CAP_CC</c>. This carrier holds no
/// pooled memory — each element is a 4-octet value type — so the bound enforced here is the buffer-capacity
/// guard <see cref="TpmReader.EnsureCount"/> applies across the list types: a count that could not possibly fit
/// in the remaining wire bytes is refused before it can size an allocation.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.8.2, Table 123.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlCca: ITpmWireType
{
    /// <summary>
    /// The shared zero-length instance backing every empty list.
    /// </summary>
    private static TpmlCca EmptyInstance { get; } = new(ImmutableArray<TpmaCc>.Empty);

    /// <summary>
    /// Initializes a new command-attribute list.
    /// </summary>
    /// <param name="commandAttributes">The command attributes.</param>
    private TpmlCca(ImmutableArray<TpmaCc> commandAttributes)
    {
        CommandAttributes = commandAttributes;
    }

    /// <summary>
    /// Gets an empty command-attribute list.
    /// </summary>
    public static TpmlCca Empty => EmptyInstance;

    /// <summary>
    /// Gets the command attributes.
    /// </summary>
    public ImmutableArray<TpmaCc> CommandAttributes { get; }

    /// <summary>
    /// Gets the number of command attributes.
    /// </summary>
    public int Count => CommandAttributes.Length;

    /// <summary>
    /// Gets whether this list is empty.
    /// </summary>
    public bool IsEmpty => CommandAttributes.Length == 0;

    /// <summary>
    /// Gets the command attribute at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The command attribute.</returns>
    public TpmaCc this[int index] => CommandAttributes[index];

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(uint) + (CommandAttributes.Length * sizeof(uint));

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)CommandAttributes.Length);

        foreach(TpmaCc commandAttribute in CommandAttributes)
        {
            writer.WriteUInt32(commandAttribute.Value);
        }
    }

    /// <summary>
    /// Parses a command-attribute list from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed command-attribute list.</returns>
    /// <exception cref="InvalidOperationException">The count exceeds what the remaining buffer can hold. This is a host-side refusal of a malformed response and carries no TPM response code: <c>TPML_CCA</c> is returned by the TPM and never entered into it (Part 2, clause 10.9.1, Table 138, printed page 152 selects it for <c>TPM_CAP_COMMANDS</c>), and unlike its <c>TPML_CC</c> and <c>TPML_ALG</c> siblings Table 123, printed page 146 carries no <c>#TPM_RC_SIZE</c> row.</exception>
    public static TpmlCca Parse(ref TpmReader reader)
    {
        uint count = reader.ReadUInt32();

        if(count == 0)
        {
            return Empty;
        }

        //Each TPMA_CC occupies 4 octets on the wire, so a count larger than the remaining buffer can hold is a
        //malformed length and must not size the backing array (Part 2, clause 10.8.2).
        reader.EnsureCount(count, sizeof(uint));

        var builder = ImmutableArray.CreateBuilder<TpmaCc>((int)count);
        for(int i = 0; i < count; i++)
        {
            builder.Add(new TpmaCc(reader.ReadUInt32()));
        }

        return new TpmlCca(builder.MoveToImmutable());
    }

    /// <summary>
    /// The debugger's one-line rendering: the entry count only, never the attribute words themselves.
    /// </summary>
    private string DebuggerDisplay => $"TPML_CCA({CommandAttributes.Length} command attributes)";
}
