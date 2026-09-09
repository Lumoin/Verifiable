using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Symmetric block cipher object parameters (TPMS_SYMCIPHER_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// "This Table 165 structure contains the parameters for a symmetric block cipher object" — the algorithm
/// details a <c>TPM_ALG_SYMCIPHER</c> public area or a <see cref="TpmtPublicParms"/> selects.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMT_SYM_DEF_OBJECT sym;                 // The symmetric algorithm, key size, and mode.
/// } TPMS_SYMCIPHER_PARMS;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.1.9, Table 165.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsSymcipherParms
{
    /// <summary>
    /// Gets the symmetric algorithm, key size, and mode.
    /// </summary>
    public TpmtSymDefObject Sym { get; init; }

    /// <summary>
    /// Creates symmetric block cipher parameters.
    /// </summary>
    /// <param name="sym">The symmetric algorithm definition.</param>
    /// <returns>The symmetric block cipher parameters.</returns>
    public static TpmsSymcipherParms Create(TpmtSymDefObject sym) => new()
    {
        Sym = sym
    };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => Sym.SerializedSize;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        Sym.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses symmetric block cipher parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed parameters.</returns>
    public static TpmsSymcipherParms Parse(ref TpmReader reader) =>
        new()
        {
            Sym = TpmtSymDefObject.Parse(ref reader)
        };

    /// <summary>The debugger's one-line rendering: the structure's name and its symmetric algorithm.</summary>
    private string DebuggerDisplay => $"TPMS_SYMCIPHER_PARMS({Sym.Algorithm})";
}
