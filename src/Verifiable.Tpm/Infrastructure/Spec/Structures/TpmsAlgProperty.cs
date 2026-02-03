using System;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPMS_ALG_PROPERTY - algorithm property.
/// </summary>
/// <remarks>
/// <para>
/// This structure is returned by TPM2_GetCapability when querying TPM_CAP_ALGS.
/// Each entry contains an algorithm identifier and its attributes.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_ALG_ID       alg;            // An algorithm identifier.
///     TPMA_ALGORITHM   algProperties;  // The attributes of the algorithm.
/// } TPMS_ALG_PROPERTY;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.6.1, Table 108.
/// </para>
/// </remarks>
/// <param name="Algorithm">The algorithm identifier.</param>
/// <param name="AlgorithmAttributes">The algorithm attributes.</param>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsAlgProperty(TpmAlgIdConstants Algorithm, TpmaAlgorithm AlgorithmAttributes)
{
    /// <summary>
    /// Parses an algorithm property from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <returns>The parsed algorithm property.</returns>
    public static TpmsAlgProperty Parse(ref TpmReader reader)
    {
        ushort alg = reader.ReadUInt16();
        uint attributes = reader.ReadUInt32();

        return new TpmsAlgProperty((TpmAlgIdConstants)alg, (TpmaAlgorithm)attributes);
    }

    /// <summary>
    /// Gets whether this algorithm is asymmetric.
    /// </summary>
    public bool IsAsymmetric => AlgorithmAttributes.HasFlag(TpmaAlgorithm.ASYMMETRIC);

    /// <summary>
    /// Gets whether this algorithm is symmetric.
    /// </summary>
    public bool IsSymmetric => AlgorithmAttributes.HasFlag(TpmaAlgorithm.SYMMETRIC);

    /// <summary>
    /// Gets whether this algorithm is a hash.
    /// </summary>
    public bool IsHash => AlgorithmAttributes.HasFlag(TpmaAlgorithm.HASH);

    /// <summary>
    /// Gets whether this algorithm is an object type.
    /// </summary>
    public bool IsObject => AlgorithmAttributes.HasFlag(TpmaAlgorithm.OBJECT);

    /// <summary>
    /// Gets whether this algorithm is a signing algorithm.
    /// </summary>
    public bool IsSigning => AlgorithmAttributes.HasFlag(TpmaAlgorithm.SIGNING);

    /// <summary>
    /// Gets whether this algorithm is an encryption algorithm.
    /// </summary>
    public bool IsEncrypting => AlgorithmAttributes.HasFlag(TpmaAlgorithm.ENCRYPTING);

    /// <summary>
    /// Gets whether this algorithm is a method (e.g., KDF).
    /// </summary>
    public bool IsMethod => AlgorithmAttributes.HasFlag(TpmaAlgorithm.METHOD);

    private string DebuggerDisplay => $"TPMS_ALG_PROPERTY({Algorithm}, {AlgorithmAttributes})";
}