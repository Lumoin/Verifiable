using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Algorithm parameters checked by <c>TPM2_TestParms()</c> (TPMT_PUBLIC_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// "This Table 234 structure is used in TPM2_TestParms() to validate that a set of algorithm parameters is
/// supported by the TPM." <see cref="Type"/> is "the algorithm to be tested" and <see cref="Parameters"/> is
/// "the algorithm details" the selector chooses.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_PUBLIC type;                    // The algorithm to be tested.
///     TPMU_PUBLIC_PARMS parameters;            // [type] The algorithm details.
/// } TPMT_PUBLIC_PARMS;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 12.2.3.10, Table 234 — distinct from the Part 3
/// command table Part 3 also numbers Table 234 (<c>TPM2_ClockSet()</c>'s handle/parameter table); the two
/// share a table number only because Part 2 and Part 3 number tables independently.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmtPublicParms
{
    /// <summary>
    /// Gets the algorithm to be tested.
    /// </summary>
    public TpmAlgIdConstants Type { get; init; }

    /// <summary>
    /// Gets the algorithm details <see cref="Type"/> selects.
    /// </summary>
    public TpmuPublicParms Parameters { get; init; }

    /// <summary>
    /// Creates the parameters <c>TPM2_TestParms()</c> validates.
    /// </summary>
    /// <param name="type">The algorithm to be tested.</param>
    /// <param name="parameters">The algorithm details.</param>
    /// <returns>The parameters structure.</returns>
    public static TpmtPublicParms Create(TpmAlgIdConstants type, TpmuPublicParms parameters) => new()
    {
        Type = type,
        Parameters = parameters
    };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Parameters.SerializedSize;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Type);
        Parameters.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses <c>TPM2_TestParms()</c>'s parameters from a TPM reader: the selector, then the union arm it
    /// chooses (<see cref="TpmuPublicParms.Parse"/>).
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed parameters.</returns>
    public static TpmtPublicParms Parse(ref TpmReader reader)
    {
        var type = (TpmAlgIdConstants)reader.ReadUInt16();
        TpmuPublicParms parameters = TpmuPublicParms.Parse(type, ref reader);

        return new TpmtPublicParms { Type = type, Parameters = parameters };
    }

    /// <summary>The debugger's one-line rendering: the structure's name and its selected public-area type.</summary>
    private string DebuggerDisplay => $"TPMT_PUBLIC_PARMS({Type})";
}
