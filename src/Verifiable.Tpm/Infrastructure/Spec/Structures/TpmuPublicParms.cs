using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Union of public key parameters (TPMU_PUBLIC_PARMS).
/// </summary>
/// <remarks>
/// <para>
/// This union contains algorithm-specific parameters for the public area of a key.
/// The actual content is determined by the algorithm type.
/// </para>
/// <para>
/// <b>Union members:</b>
/// </para>
/// <list type="bullet">
///   <item><description>TPM_ALG_KEYEDHASH: TPMS_KEYEDHASH_PARMS</description></item>
///   <item><description>TPM_ALG_SYMCIPHER: TPMS_SYMCIPHER_PARMS</description></item>
///   <item><description>TPM_ALG_RSA: TPMS_RSA_PARMS</description></item>
///   <item><description>TPM_ALG_ECC: TPMS_ECC_PARMS</description></item>
///   <item><description>TPM_ALG_MLDSA: TPMS_MLDSA_PARMS</description></item>
///   <item><description>TPM_ALG_HASH_MLDSA: TPMS_HASH_MLDSA_PARMS</description></item>
///   <item><description>TPM_ALG_MLKEM: TPMS_MLKEM_PARMS</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.7, Table 217 (v1.85).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct TpmuPublicParms: IEquatable<TpmuPublicParms>
{
    /// <summary>
    /// Gets the algorithm type that determines union interpretation.
    /// </summary>
    public TpmAlgIdConstants Type { get; init; }

    /// <summary>
    /// Gets the RSA parameters (when Type is TPM_ALG_RSA).
    /// </summary>
    public TpmsRsaParms? RsaDetail { get; init; }

    /// <summary>
    /// Gets the ECC parameters (when Type is TPM_ALG_ECC).
    /// </summary>
    public TpmsEccParms? EccDetail { get; init; }

    /// <summary>
    /// Gets the ML-DSA parameters (when Type is TPM_ALG_MLDSA).
    /// </summary>
    public TpmsMlDsaParms? MlDsaDetail { get; init; }

    /// <summary>
    /// Gets the Pre-Hash ML-DSA parameters (when Type is TPM_ALG_HASH_MLDSA).
    /// </summary>
    public TpmsHashMlDsaParms? HashMlDsaDetail { get; init; }

    /// <summary>
    /// Gets the ML-KEM parameters (when Type is TPM_ALG_MLKEM).
    /// </summary>
    public TpmsMlKemParms? MlKemDetail { get; init; }

    /// <summary>
    /// Creates RSA public parameters.
    /// </summary>
    /// <param name="rsaParms">The RSA parameters.</param>
    /// <returns>The union containing RSA parameters.</returns>
    public static TpmuPublicParms Rsa(TpmsRsaParms rsaParms) => new()
    {
        Type = TpmAlgIdConstants.TPM_ALG_RSA,
        RsaDetail = rsaParms
    };

    /// <summary>
    /// Creates ECC public parameters.
    /// </summary>
    /// <param name="eccParms">The ECC parameters.</param>
    /// <returns>The union containing ECC parameters.</returns>
    public static TpmuPublicParms Ecc(TpmsEccParms eccParms) => new()
    {
        Type = TpmAlgIdConstants.TPM_ALG_ECC,
        EccDetail = eccParms
    };

    /// <summary>
    /// Creates ML-DSA public parameters.
    /// </summary>
    /// <param name="mlDsaParms">The ML-DSA parameters.</param>
    /// <returns>The union containing ML-DSA parameters.</returns>
    public static TpmuPublicParms MlDsa(TpmsMlDsaParms mlDsaParms) => new()
    {
        Type = TpmAlgIdConstants.TPM_ALG_MLDSA,
        MlDsaDetail = mlDsaParms
    };

    /// <summary>
    /// Creates Pre-Hash ML-DSA public parameters.
    /// </summary>
    /// <param name="hashMlDsaParms">The Pre-Hash ML-DSA parameters.</param>
    /// <returns>The union containing Pre-Hash ML-DSA parameters.</returns>
    public static TpmuPublicParms HashMlDsa(TpmsHashMlDsaParms hashMlDsaParms) => new()
    {
        Type = TpmAlgIdConstants.TPM_ALG_HASH_MLDSA,
        HashMlDsaDetail = hashMlDsaParms
    };

    /// <summary>
    /// Creates ML-KEM public parameters.
    /// </summary>
    /// <param name="mlKemParms">The ML-KEM parameters.</param>
    /// <returns>The union containing ML-KEM parameters.</returns>
    public static TpmuPublicParms MlKem(TpmsMlKemParms mlKemParms) => new()
    {
        Type = TpmAlgIdConstants.TPM_ALG_MLKEM,
        MlKemDetail = mlKemParms
    };

    /// <summary>
    /// Gets the serialized size of this union.
    /// </summary>
    public int GetSerializedSize() => Type switch
    {
        TpmAlgIdConstants.TPM_ALG_RSA => RsaDetail!.Value.GetSerializedSize(),
        TpmAlgIdConstants.TPM_ALG_ECC => EccDetail!.Value.GetSerializedSize(),
        TpmAlgIdConstants.TPM_ALG_MLDSA => MlDsaDetail!.Value.GetSerializedSize(),
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => HashMlDsaDetail!.Value.GetSerializedSize(),
        TpmAlgIdConstants.TPM_ALG_MLKEM => MlKemDetail!.Value.GetSerializedSize(),
        _ => throw new NotSupportedException($"Algorithm type '{Type}' is not supported for serialization.")
    };

    /// <summary>
    /// Writes this union to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <remarks>
    /// The type selector is not written; it must be written separately as part of TPMT_PUBLIC.
    /// </remarks>
    public void WriteTo(ref TpmWriter writer)
    {
        switch(Type)
        {
            case TpmAlgIdConstants.TPM_ALG_RSA:
                RsaDetail!.Value.WriteTo(ref writer);
                break;
            case TpmAlgIdConstants.TPM_ALG_ECC:
                EccDetail!.Value.WriteTo(ref writer);
                break;
            case TpmAlgIdConstants.TPM_ALG_MLDSA:
                MlDsaDetail!.Value.WriteTo(ref writer);
                break;
            case TpmAlgIdConstants.TPM_ALG_HASH_MLDSA:
                HashMlDsaDetail!.Value.WriteTo(ref writer);
                break;
            case TpmAlgIdConstants.TPM_ALG_MLKEM:
                MlKemDetail!.Value.WriteTo(ref writer);
                break;
            default:
                throw new NotSupportedException($"Algorithm type '{Type}' is not supported for serialization.");
        }
    }

    /// <summary>
    /// Parses public parameters from a TPM reader.
    /// </summary>
    /// <param name="type">The algorithm type (selector).</param>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed public parameters.</returns>
    public static TpmuPublicParms Parse(TpmAlgIdConstants type, ref TpmReader reader) => type switch
    {
        TpmAlgIdConstants.TPM_ALG_RSA => new TpmuPublicParms
        {
            Type = type,
            RsaDetail = TpmsRsaParms.Parse(ref reader)
        },
        TpmAlgIdConstants.TPM_ALG_ECC => new TpmuPublicParms
        {
            Type = type,
            EccDetail = TpmsEccParms.Parse(ref reader)
        },
        TpmAlgIdConstants.TPM_ALG_MLDSA => new TpmuPublicParms
        {
            Type = type,
            MlDsaDetail = TpmsMlDsaParms.Parse(ref reader)
        },
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => new TpmuPublicParms
        {
            Type = type,
            HashMlDsaDetail = TpmsHashMlDsaParms.Parse(ref reader)
        },
        TpmAlgIdConstants.TPM_ALG_MLKEM => new TpmuPublicParms
        {
            Type = type,
            MlKemDetail = TpmsMlKemParms.Parse(ref reader)
        },
        _ => throw new NotSupportedException($"Algorithm type '{type}' is not supported for parsing.")
    };

    /// <inheritdoc/>
    public bool Equals(TpmuPublicParms other) =>
        Type == other.Type &&
        Nullable.Equals(RsaDetail, other.RsaDetail) &&
        Nullable.Equals(EccDetail, other.EccDetail) &&
        Nullable.Equals(MlDsaDetail, other.MlDsaDetail) &&
        Nullable.Equals(HashMlDsaDetail, other.HashMlDsaDetail) &&
        Nullable.Equals(MlKemDetail, other.MlKemDetail);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is TpmuPublicParms other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Type, RsaDetail, EccDetail, MlDsaDetail, HashMlDsaDetail, MlKemDetail);

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(TpmuPublicParms left, TpmuPublicParms right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(TpmuPublicParms left, TpmuPublicParms right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPMU_PUBLIC_PARMS({Type})";
}