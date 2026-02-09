using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_ALGORITHM - algorithm attribute bits.
/// </summary>
/// <remarks>
/// <para>
/// Defines the attributes of an algorithm (asymmetric, symmetric, hash) and whether it is used for objects,
/// signing, encryption/decryption, or as a method (e.g., KDF).
/// </para>
/// <para>
/// Used in algorithm property lists returned by <c>TPM2_GetCapability(capability == TPM_CAP_ALGS)</c>.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.2 (TPMA_ALGORITHM).
/// </para>
/// </remarks>
[Flags]
[SuppressMessage("Naming", "CA1720:Identifier contains type name", Justification = "Enum values defined by TPM 2.0 specification.")]
public enum TpmaAlgorithm: uint
{
    /// <summary>
    /// ASYMMETRIC (bit 0):
    /// SET (1) indicates an asymmetric algorithm with public and private portions; CLEAR (0) indicates not an asymmetric algorithm.
    /// </summary>
    ASYMMETRIC = 0x0000_0001,

    /// <summary>
    /// SYMMETRIC (bit 1):
    /// SET (1) indicates a symmetric block cipher; CLEAR (0) indicates not a symmetric block cipher.
    /// </summary>
    SYMMETRIC = 0x0000_0002,

    /// <summary>
    /// HASH (bit 2):
    /// SET (1) indicates a hash algorithm; CLEAR (0) indicates not a hash algorithm.
    /// </summary>
    HASH = 0x0000_0004,

    /// <summary>
    /// OBJECT (bit 3):
    /// SET (1) indicates an algorithm that may be used as an object type; CLEAR (0) indicates not used as an object type.
    /// </summary>
    OBJECT = 0x0000_0008,

    /// <summary>
    /// SIGNING (bit 8):
    /// SET (1) indicates a signing algorithm. The setting of ASYMMETRIC, SYMMETRIC, and HASH indicates the type of signing algorithm.
    /// CLEAR (0) indicates not a signing algorithm.
    /// </summary>
    SIGNING = 0x0000_0100,

    /// <summary>
    /// ENCRYPTING (bit 9):
    /// SET (1) indicates an encryption/decryption algorithm. The setting of ASYMMETRIC, SYMMETRIC, and HASH indicates the type of
    /// encryption/decryption algorithm. CLEAR (0) indicates not an encryption/decryption algorithm.
    /// </summary>
    ENCRYPTING = 0x0000_0200,

    /// <summary>
    /// METHOD (bit 10):
    /// SET (1) indicates a method such as a key-derivative function (KDF); CLEAR (0) indicates not a method.
    /// </summary>
    METHOD = 0x0000_0400
}
