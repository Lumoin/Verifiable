using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_ALG_SYM — a selector constrained to the symmetric algorithms implemented on the TPM.
/// </summary>
/// <remarks>
/// <para>
/// Used wherever a command or structure names a symmetric algorithm rather than a specific block cipher plus
/// mode (for example the algorithm half of a <c>TPMT_SYM_DEF</c>).
/// </para>
/// <para>
/// <b>Valid values:</b> the symmetric block ciphers — <c>TPM_ALG_AES</c>, <c>TPM_ALG_SM4</c>,
/// <c>TPM_ALG_CAMELLIA</c>, <c>TPM_ALG_TDES</c> — plus <c>TPM_ALG_XOR</c>, required to be present, and —
/// where the embedding structure admits it (the table's leading <c>+</c>) — <c>TPM_ALG_NULL</c>, also
/// required to be present in all versions of this table. Unmarshaling any other value is
/// <c>TPM_RC_SYMMETRIC</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 9.33, Table 79.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiAlgSym
{
    /// <summary>
    /// Gets the raw algorithm selector.
    /// </summary>
    public TpmAlgIdConstants Value { get; }

    /// <summary>
    /// Initializes a symmetric algorithm selector from a raw value.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    public TpmiAlgSym(TpmAlgIdConstants value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets whether this selector is <c>TPM_ALG_NULL</c>.
    /// </summary>
    public bool IsNull => Value == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Whether a raw algorithm value is one of the symmetric algorithms this type admits.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsAlgSym(TpmAlgIdConstants value, bool isNullAdmitted = false) => value switch
    {
        TpmAlgIdConstants.TPM_ALG_AES or
        TpmAlgIdConstants.TPM_ALG_SM4 or
        TpmAlgIdConstants.TPM_ALG_CAMELLIA or
        TpmAlgIdConstants.TPM_ALG_TDES or
        TpmAlgIdConstants.TPM_ALG_XOR => true,
        TpmAlgIdConstants.TPM_ALG_NULL => isNullAdmitted,
        TpmAlgIdConstants.TPM_ALG_ERROR => false,
        TpmAlgIdConstants.TPM_ALG_RSA => false,
        TpmAlgIdConstants.TPM_ALG_SHA => false,
        TpmAlgIdConstants.TPM_ALG_HMAC => false,
        TpmAlgIdConstants.TPM_ALG_MGF1 => false,
        TpmAlgIdConstants.TPM_ALG_KEYEDHASH => false,
        TpmAlgIdConstants.TPM_ALG_SHA256 => false,
        TpmAlgIdConstants.TPM_ALG_SHA384 => false,
        TpmAlgIdConstants.TPM_ALG_SHA512 => false,
        TpmAlgIdConstants.TPM_ALG_SHA256_192 => false,
        TpmAlgIdConstants.TPM_ALG_SM3_256 => false,
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
        TpmAlgIdConstants.TPM_ALG_ECC => false,
        TpmAlgIdConstants.TPM_ALG_SYMCIPHER => false,
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
        TpmAlgIdConstants.TPM_ALG_MLKEM => false,
        TpmAlgIdConstants.TPM_ALG_MLDSA => false,
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => false,
        _ => false
    };

    /// <summary>
    /// Parses a symmetric algorithm selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not an admitted symmetric algorithm (<c>TPM_RC_SYMMETRIC</c>).</exception>
    public static TpmiAlgSym Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        var value = (TpmAlgIdConstants)reader.ReadUInt16();
        if(!IsAlgSym(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid symmetric algorithm 0x{(ushort)value:X4}. Expected a symmetric block cipher or TPM_ALG_XOR{(isNullAdmitted ? ", or TPM_ALG_NULL" : string.Empty)}.");
        }

        return new TpmiAlgSym(value);
    }

    /// <summary>
    /// Creates a symmetric algorithm selector from a raw value without validation — for a value already known
    /// good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns>The selector.</returns>
    public static TpmiAlgSym FromValue(TpmAlgIdConstants value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16((ushort)Value);

    private string DebuggerDisplay => $"TPMI_ALG_SYM({Value})";
}
