using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Pre-Hash ML-DSA key parameters structure (TPMS_HASH_MLDSA_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// Contains the parameters for Pre-Hash ML-DSA (HashML-DSA) keys.
/// Pre-Hash ML-DSA is a variant where the message is hashed before signing.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_MLDSA_PARAMETER_SET parameterSet; // ML-DSA parameter set ID.
///     TPMI_ALG_HASH            hashAlg;      // The pre-hash function PH.
/// } TPMS_HASH_MLDSA_PARMS;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.7, Table 229 (v1.85).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct TpmsHashMlDsaParms: IEquatable<TpmsHashMlDsaParms>
{
    /// <summary>
    /// Gets the ML-DSA parameter set.
    /// </summary>
    /// <remarks>
    /// One of: TPM_MLDSA_44, TPM_MLDSA_65, or TPM_MLDSA_87.
    /// </remarks>
    public TpmMlDsaParameterSet ParameterSet { get; init; }

    /// <summary>
    /// Gets the pre-hash function algorithm.
    /// </summary>
    /// <remarks>
    /// The hash algorithm used to digest the message before signing.
    /// Common values: TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512.
    /// </remarks>
    public TpmAlgIdConstants HashAlg { get; init; }

    /// <summary>
    /// Creates a new Pre-Hash ML-DSA parameters structure.
    /// </summary>
    /// <param name="parameterSet">The ML-DSA parameter set.</param>
    /// <param name="hashAlg">The pre-hash function algorithm.</param>
    /// <returns>The Pre-Hash ML-DSA parameters.</returns>
    public static TpmsHashMlDsaParms Create(TpmMlDsaParameterSet parameterSet, TpmAlgIdConstants hashAlg) => new()
    {
        ParameterSet = parameterSet,
        HashAlg = hashAlg
    };

    /// <summary>
    /// Creates Pre-Hash ML-DSA-44 parameters with SHA-256.
    /// </summary>
    /// <returns>The Pre-Hash ML-DSA-44 parameters.</returns>
    public static TpmsHashMlDsaParms HashMlDsa44Sha256() =>
        Create(TpmMlDsaParameterSet.TPM_MLDSA_44, TpmAlgIdConstants.TPM_ALG_SHA256);

    /// <summary>
    /// Creates Pre-Hash ML-DSA-65 parameters with SHA-384.
    /// </summary>
    /// <returns>The Pre-Hash ML-DSA-65 parameters.</returns>
    public static TpmsHashMlDsaParms HashMlDsa65Sha384() =>
        Create(TpmMlDsaParameterSet.TPM_MLDSA_65, TpmAlgIdConstants.TPM_ALG_SHA384);

    /// <summary>
    /// Creates Pre-Hash ML-DSA-87 parameters with SHA-512.
    /// </summary>
    /// <returns>The Pre-Hash ML-DSA-87 parameters.</returns>
    public static TpmsHashMlDsaParms HashMlDsa87Sha512() =>
        Create(TpmMlDsaParameterSet.TPM_MLDSA_87, TpmAlgIdConstants.TPM_ALG_SHA512);

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public static int SerializedSize => sizeof(ushort) + sizeof(ushort);

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)ParameterSet);
        writer.WriteUInt16((ushort)HashAlg);
    }

    /// <summary>
    /// Parses Pre-Hash ML-DSA parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed Pre-Hash ML-DSA parameters.</returns>
    public static TpmsHashMlDsaParms Parse(ref TpmReader reader)
    {
        var parameterSet = (TpmMlDsaParameterSet)reader.ReadUInt16();
        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        return new TpmsHashMlDsaParms
        {
            ParameterSet = parameterSet,
            HashAlg = hashAlg
        };
    }

    /// <inheritdoc/>
    public bool Equals(TpmsHashMlDsaParms other) =>
        ParameterSet == other.ParameterSet && HashAlg == other.HashAlg;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is TpmsHashMlDsaParms other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(ParameterSet, HashAlg);

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(TpmsHashMlDsaParms left, TpmsHashMlDsaParms right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(TpmsHashMlDsaParms left, TpmsHashMlDsaParms right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPMS_HASH_MLDSA_PARMS({ParameterSet}, {HashAlg})";
}