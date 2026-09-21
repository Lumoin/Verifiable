using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_ALG_PUBLIC — a selector constrained to the object types a public area may declare.
/// </summary>
/// <remarks>
/// <para>
/// Used as the <c>type</c> of a <c>TPMT_PUBLIC</c>, choosing the object-specific parameters and unique field
/// shape a public area carries.
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_ALG_RSA</c>, <c>TPM_ALG_KEYEDHASH</c>, <c>TPM_ALG_ECC</c>,
/// <c>TPM_ALG_SYMCIPHER</c>, <c>TPM_ALG_MLDSA</c>, <c>TPM_ALG_HASH_MLDSA</c>, and <c>TPM_ALG_MLKEM</c> —
/// the seven names Table 225 enumerates. Unlike the hash and scheme interface types, that table carries no
/// leading <c>+</c>, so <c>TPM_ALG_NULL</c> is never admitted. Unmarshaling any other value is
/// <c>TPM_RC_TYPE</c>.
/// </para>
/// <para>
/// Part 2 v185 (2026/03/12, Published) writes the admitted set out name by name in clause 12.2.2,
/// Table 225, and clause 6.3, Table 8 places the three lattice names inside its Object Types group:
/// <c>TPM_ALG_MLKEM</c> 0x00A0, <c>TPM_ALG_MLDSA</c> 0x00A1, and <c>TPM_ALG_HASH_MLDSA</c> 0x00A2. The
/// printed v184 text names the same class by reference instead of by enumeration — clause 12.2.2,
/// Table 211's single row <c>TPM_ALG_!ALG.o</c>, "all object types", the algorithm-registry expression for
/// every algorithm the registry marks as an object type.
/// </para>
/// <para>
/// <see cref="Verifiable.Tpm.Spec.Structures.TpmuPublicParms"/> and
/// <see cref="Verifiable.Tpm.Spec.Structures.TpmtPublic"/> select object parameters on all seven.
/// Admission is not implementation mandate: the TCG PC Client Platform TPM Profile 1.07 marks
/// <c>TPM_ALG_MLKEM</c> and <c>TPM_ALG_MLDSA</c> Mandatory but <c>TPM_ALG_HASH_MLDSA</c> Optional, so a
/// conformant TPM may implement a proper subset of what this selector accepts.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 12.2.2 — Table 225 (v185), Table 211 (v184).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiAlgPublic
{
    /// <summary>
    /// Gets the raw algorithm selector.
    /// </summary>
    public TpmAlgIdConstants Value { get; }

    /// <summary>
    /// Initializes a public object type selector from a raw value.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    public TpmiAlgPublic(TpmAlgIdConstants value)
    {
        Value = value;
    }

    /// <summary>
    /// Whether a raw algorithm value is one of the public object types this type admits.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsPublic(TpmAlgIdConstants value) => value switch
    {
        TpmAlgIdConstants.TPM_ALG_RSA or
        TpmAlgIdConstants.TPM_ALG_ECC or
        TpmAlgIdConstants.TPM_ALG_KEYEDHASH or
        TpmAlgIdConstants.TPM_ALG_SYMCIPHER or
        TpmAlgIdConstants.TPM_ALG_MLDSA or
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA or
        TpmAlgIdConstants.TPM_ALG_MLKEM => true,
        TpmAlgIdConstants.TPM_ALG_ERROR => false,
        TpmAlgIdConstants.TPM_ALG_TDES => false,
        TpmAlgIdConstants.TPM_ALG_SHA => false,
        TpmAlgIdConstants.TPM_ALG_HMAC => false,
        TpmAlgIdConstants.TPM_ALG_AES => false,
        TpmAlgIdConstants.TPM_ALG_MGF1 => false,
        TpmAlgIdConstants.TPM_ALG_XOR => false,
        TpmAlgIdConstants.TPM_ALG_SHA256 => false,
        TpmAlgIdConstants.TPM_ALG_SHA384 => false,
        TpmAlgIdConstants.TPM_ALG_SHA512 => false,
        TpmAlgIdConstants.TPM_ALG_SHA256_192 => false,
        TpmAlgIdConstants.TPM_ALG_NULL => false,
        TpmAlgIdConstants.TPM_ALG_SM3_256 => false,
        TpmAlgIdConstants.TPM_ALG_SM4 => false,
        TpmAlgIdConstants.TPM_ALG_RSASSA => false,
        TpmAlgIdConstants.TPM_ALG_RSAES => false,
        TpmAlgIdConstants.TPM_ALG_RSAPSS => false,
        TpmAlgIdConstants.TPM_ALG_OAEP => false,
        TpmAlgIdConstants.TPM_ALG_ECDSA => false,
        TpmAlgIdConstants.TPM_ALG_ECDH => false,
        TpmAlgIdConstants.TPM_ALG_ECDAA => false,
        TpmAlgIdConstants.TPM_ALG_SM2 => false,
        TpmAlgIdConstants.TPM_ALG_ECSCHNORR => false,
        TpmAlgIdConstants.TPM_ALG_ECMQV => false,
        TpmAlgIdConstants.TPM_ALG_HKDF => false,
        TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A => false,
        TpmAlgIdConstants.TPM_ALG_KDF2 => false,
        TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 => false,
        TpmAlgIdConstants.TPM_ALG_CAMELLIA => false,
        TpmAlgIdConstants.TPM_ALG_SHA3_256 => false,
        TpmAlgIdConstants.TPM_ALG_SHA3_384 => false,
        TpmAlgIdConstants.TPM_ALG_SHA3_512 => false,
        TpmAlgIdConstants.TPM_ALG_SHAKE128 => false,
        TpmAlgIdConstants.TPM_ALG_SHAKE256 => false,
        TpmAlgIdConstants.TPM_ALG_SHAKE256_192 => false,
        TpmAlgIdConstants.TPM_ALG_SHAKE256_256 => false,
        TpmAlgIdConstants.TPM_ALG_SHAKE256_512 => false,
        TpmAlgIdConstants.TPM_ALG_CMAC => false,
        TpmAlgIdConstants.TPM_ALG_CTR => false,
        TpmAlgIdConstants.TPM_ALG_OFB => false,
        TpmAlgIdConstants.TPM_ALG_CBC => false,
        TpmAlgIdConstants.TPM_ALG_CFB => false,
        TpmAlgIdConstants.TPM_ALG_ECB => false,
        TpmAlgIdConstants.TPM_ALG_CCM => false,
        TpmAlgIdConstants.TPM_ALG_GCM => false,
        TpmAlgIdConstants.TPM_ALG_KW => false,
        TpmAlgIdConstants.TPM_ALG_KWP => false,
        TpmAlgIdConstants.TPM_ALG_EAX => false,
        TpmAlgIdConstants.TPM_ALG_EDDSA => false,
        TpmAlgIdConstants.TPM_ALG_EDDSA_PH => false,
        TpmAlgIdConstants.TPM_ALG_LMS => false,
        TpmAlgIdConstants.TPM_ALG_XMSS => false,
        TpmAlgIdConstants.TPM_ALG_KEYEDXOF => false,
        TpmAlgIdConstants.TPM_ALG_KMACXOF128 => false,
        TpmAlgIdConstants.TPM_ALG_KMACXOF256 => false,
        TpmAlgIdConstants.TPM_ALG_KMAC128 => false,
        TpmAlgIdConstants.TPM_ALG_KMAC256 => false,
        _ => false
    };

    /// <summary>
    /// Parses a public object type selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet selector.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not an admitted object type (<c>TPM_RC_TYPE</c>).</exception>
    public static TpmiAlgPublic Parse(ref TpmReader reader)
    {
        var value = (TpmAlgIdConstants)reader.ReadUInt16();
        if(!IsPublic(value))
        {
            throw new InvalidOperationException($"Invalid public object type 0x{(ushort)value:X4}. Expected TPM_ALG_RSA, TPM_ALG_ECC, TPM_ALG_KEYEDHASH, TPM_ALG_SYMCIPHER, TPM_ALG_MLDSA, TPM_ALG_HASH_MLDSA, or TPM_ALG_MLKEM.");
        }

        return new TpmiAlgPublic(value);
    }

    /// <summary>
    /// Creates a public object type selector from a raw value without validation — for a value already known
    /// good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns>The selector.</returns>
    public static TpmiAlgPublic FromValue(TpmAlgIdConstants value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16((ushort)Value);

    private string DebuggerDisplay => $"TPMI_ALG_PUBLIC({Value})";
}
