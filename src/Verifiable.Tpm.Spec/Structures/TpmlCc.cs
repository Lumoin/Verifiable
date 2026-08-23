using System;
using System.Collections.Immutable;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// List of command codes (TPML_CC).
/// </summary>
/// <remarks>
/// <para>
/// May be input to the TPM (for example <c>TPM2_PP_Commands()</c>'s command lists) or returned by it (for
/// example <c>TPM2_GetCapability()</c> with <c>capability == TPM_CAP_COMMANDS</c>, via <c>TPML_CCA</c>'s
/// sibling command-code list).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                            // Number of command codes; may be 0.
///     TPM_CC commandCodes[count];               // The command codes.
/// } TPML_CC;
/// </code>
/// <para>
/// Part 2, Table 119 bounds an input <c>count</c> by the implementation-dependent <c>MAX_CAP_CC</c> ("The
/// maximum only applies to a command code list in a command. The response size is limited only by the size of
/// the parameter buffer") and names <c>TPM_RC_SIZE</c> as the response when it is exceeded. This carrier holds
/// no pooled memory — each element is a 4-octet value type — so the bound enforced here is the buffer-capacity
/// guard <see cref="TpmReader.EnsureCount"/> already applies to <see cref="TpmlDigest"/>: a count that could
/// not possibly fit in the remaining wire bytes is refused before it can size an allocation.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.9.1, Table 119.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlCc: ITpmWireType
{
    private static TpmlCc EmptyInstance { get; } = new(ImmutableArray<TpmCcConstants>.Empty);

    /// <summary>
    /// Initializes a new command-code list.
    /// </summary>
    /// <param name="commandCodes">The command codes.</param>
    private TpmlCc(ImmutableArray<TpmCcConstants> commandCodes)
    {
        CommandCodes = commandCodes;
    }

    /// <summary>
    /// Gets an empty command-code list.
    /// </summary>
    public static TpmlCc Empty => EmptyInstance;

    /// <summary>
    /// Gets the command codes.
    /// </summary>
    public ImmutableArray<TpmCcConstants> CommandCodes { get; }

    /// <summary>
    /// Gets the number of command codes.
    /// </summary>
    public int Count => CommandCodes.Length;

    /// <summary>
    /// Gets whether this list is empty.
    /// </summary>
    public bool IsEmpty => CommandCodes.Length == 0;

    /// <summary>
    /// Gets the command code at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The command code.</returns>
    public TpmCcConstants this[int index] => CommandCodes[index];

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(uint) + (CommandCodes.Length * sizeof(uint));

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)CommandCodes.Length);

        foreach(TpmCcConstants commandCode in CommandCodes)
        {
            writer.WriteUInt32((uint)commandCode);
        }
    }

    /// <summary>
    /// Parses a command-code list from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed command-code list.</returns>
    /// <exception cref="InvalidOperationException">The count exceeds what the remaining buffer can hold (<c>TPM_RC_SIZE</c>).</exception>
    public static TpmlCc Parse(ref TpmReader reader)
    {
        uint count = reader.ReadUInt32();

        if(count == 0)
        {
            return Empty;
        }

        //Each command code occupies 4 octets on the wire, so a count larger than the remaining buffer can hold
        //is a malformed length and must not size the backing array (Part 2, §10.9.1).
        reader.EnsureCount(count, sizeof(uint));

        var builder = ImmutableArray.CreateBuilder<TpmCcConstants>((int)count);
        for(int i = 0; i < count; i++)
        {
            builder.Add((TpmCcConstants)reader.ReadUInt32());
        }

        return new TpmlCc(builder.MoveToImmutable());
    }

    private string DebuggerDisplay => $"TPML_CC({CommandCodes.Length} command codes)";
}
