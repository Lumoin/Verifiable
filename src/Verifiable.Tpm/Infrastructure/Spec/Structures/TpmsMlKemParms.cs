using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// ML-KEM key parameters structure (TPMS_MLKEM_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// Contains the parameters for ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) keys.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMT_SYM_DEF_OBJECT      symmetric;    // Symmetric algorithm for key derivation.
///     TPMI_MLKEM_PARAMETER_SET parameterSet; // ML-KEM parameter set (512/768/1024).
/// } TPMS_MLKEM_PARMS;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.6, Table 227 (v1.85).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct TpmsMlKemParms: IEquatable<TpmsMlKemParms>
{
    /// <summary>
    /// Gets the symmetric algorithm definition for key derivation.
    /// </summary>
    public TpmtSymDefObject Symmetric { get; init; }

    /// <summary>
    /// Gets the ML-KEM parameter set.
    /// </summary>
    /// <remarks>
    /// One of: TPM_MLKEM_512, TPM_MLKEM_768, or TPM_MLKEM_1024.
    /// </remarks>
    public TpmMlKemParameterSet ParameterSet { get; init; }

    /// <summary>
    /// Creates a new ML-KEM parameters structure.
    /// </summary>
    /// <param name="symmetric">The symmetric algorithm for key derivation.</param>
    /// <param name="parameterSet">The ML-KEM parameter set.</param>
    /// <returns>The ML-KEM parameters.</returns>
    public static TpmsMlKemParms Create(TpmtSymDefObject symmetric, TpmMlKemParameterSet parameterSet) => new()
    {
        Symmetric = symmetric,
        ParameterSet = parameterSet
    };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize() => Symmetric.GetSerializedSize() + sizeof(ushort);

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        Symmetric.WriteTo(ref writer);
        writer.WriteUInt16((ushort)ParameterSet);
    }

    /// <summary>
    /// Parses ML-KEM parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed ML-KEM parameters.</returns>
    public static TpmsMlKemParms Parse(ref TpmReader reader)
    {
        var symmetric = TpmtSymDefObject.Parse(ref reader);
        var parameterSet = (TpmMlKemParameterSet)reader.ReadUInt16();

        return new TpmsMlKemParms
        {
            Symmetric = symmetric,
            ParameterSet = parameterSet
        };
    }

    /// <inheritdoc/>
    public bool Equals(TpmsMlKemParms other) =>
        Symmetric.Equals(other.Symmetric) && ParameterSet == other.ParameterSet;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is TpmsMlKemParms other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Symmetric, ParameterSet);

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(TpmsMlKemParms left, TpmsMlKemParms right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(TpmsMlKemParms left, TpmsMlKemParms right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPMS_MLKEM_PARMS({ParameterSet})";
}