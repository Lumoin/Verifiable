using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// ML-DSA key parameters structure (TPMS_MLDSA_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// Contains the parameters for ML-DSA (Module-Lattice-Based Digital Signature Algorithm) keys.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_MLDSA_PARAMETER_SET parameterSet;   // ML-DSA parameter set ID.
///     TPMI_YES_NO              allowExternalMu; // Allow external Mu value.
/// } TPMS_MLDSA_PARMS;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.7, Table 228 (v1.85).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct TpmsMlDsaParms: IEquatable<TpmsMlDsaParms>
{
    /// <summary>
    /// Gets the ML-DSA parameter set.
    /// </summary>
    /// <remarks>
    /// One of: TPM_MLDSA_44, TPM_MLDSA_65, or TPM_MLDSA_87.
    /// </remarks>
    public TpmMlDsaParameterSet ParameterSet { get; init; }

    /// <summary>
    /// Gets whether external Mu is allowed for this key.
    /// </summary>
    /// <remarks>
    /// <para>
    /// If TRUE, this key can be used with TPM2_VerifyDigestSignature() and
    /// TPM2_SignDigest(). In the context of these two commands, the digest
    /// value will be interpreted as the 512-byte external Mu (μ) value as
    /// computed in Algorithm 7 (ML-DSA.Sign_internal), Line 6 of FIPS 204.
    /// </para>
    /// <para>
    /// If FALSE, this key cannot be used with TPM2_VerifyDigestSignature()
    /// and TPM2_SignDigest().
    /// </para>
    /// </remarks>
    public bool AllowExternalMu { get; init; }

    /// <summary>
    /// Creates a new ML-DSA parameters structure.
    /// </summary>
    /// <param name="parameterSet">The ML-DSA parameter set.</param>
    /// <param name="allowExternalMu">Whether to allow external Mu.</param>
    /// <returns>The ML-DSA parameters.</returns>
    public static TpmsMlDsaParms Create(TpmMlDsaParameterSet parameterSet, bool allowExternalMu = false) => new()
    {
        ParameterSet = parameterSet,
        AllowExternalMu = allowExternalMu
    };

    /// <summary>
    /// Creates ML-DSA-44 parameters.
    /// </summary>
    /// <param name="allowExternalMu">Whether to allow external Mu.</param>
    /// <returns>The ML-DSA-44 parameters.</returns>
    public static TpmsMlDsaParms MlDsa44(bool allowExternalMu = false) =>
        Create(TpmMlDsaParameterSet.TPM_MLDSA_44, allowExternalMu);

    /// <summary>
    /// Creates ML-DSA-65 parameters.
    /// </summary>
    /// <param name="allowExternalMu">Whether to allow external Mu.</param>
    /// <returns>The ML-DSA-65 parameters.</returns>
    public static TpmsMlDsaParms MlDsa65(bool allowExternalMu = false) =>
        Create(TpmMlDsaParameterSet.TPM_MLDSA_65, allowExternalMu);

    /// <summary>
    /// Creates ML-DSA-87 parameters.
    /// </summary>
    /// <param name="allowExternalMu">Whether to allow external Mu.</param>
    /// <returns>The ML-DSA-87 parameters.</returns>
    public static TpmsMlDsaParms MlDsa87(bool allowExternalMu = false) =>
        Create(TpmMlDsaParameterSet.TPM_MLDSA_87, allowExternalMu);

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize() => sizeof(ushort) + sizeof(byte);

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)ParameterSet);
        writer.WriteByte((byte)(AllowExternalMu ? 1 : 0));
    }

    /// <summary>
    /// Parses ML-DSA parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed ML-DSA parameters.</returns>
    public static TpmsMlDsaParms Parse(ref TpmReader reader)
    {
        var parameterSet = (TpmMlDsaParameterSet)reader.ReadUInt16();
        bool allowExternalMu = reader.ReadByte() != 0;

        return new TpmsMlDsaParms
        {
            ParameterSet = parameterSet,
            AllowExternalMu = allowExternalMu
        };
    }

    /// <inheritdoc/>
    public bool Equals(TpmsMlDsaParms other) =>
        ParameterSet == other.ParameterSet && AllowExternalMu == other.AllowExternalMu;

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is TpmsMlDsaParms other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(ParameterSet, AllowExternalMu);

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(TpmsMlDsaParms left, TpmsMlDsaParms right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(TpmsMlDsaParms left, TpmsMlDsaParms right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPMS_MLDSA_PARMS({ParameterSet}, ExternalMu={AllowExternalMu})";
}