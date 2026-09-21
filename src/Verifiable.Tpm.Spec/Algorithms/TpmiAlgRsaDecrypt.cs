using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Algorithms;

/// <summary>
/// TPMI_ALG_RSA_DECRYPT — a selector constrained to the RSA schemes admitted for a decryption-scheme
/// selection, as used by <c>TPM2_RSA_Encrypt()</c> and <c>TPM2_RSA_Decrypt()</c>.
/// </summary>
/// <remarks>
/// <para>
/// "The Table 192 list of values that are allowed in a decryption scheme selection as used in
/// TPM2_RSA_Encrypt() and TPM2_RSA_Decrypt()."
/// </para>
/// <para>
/// <b>Valid values:</b> <c>TPM_ALG_RSAES</c>, <c>TPM_ALG_OAEP</c> and — where the embedding structure admits
/// it (the table's leading <c>+</c>) — <c>TPM_ALG_NULL</c>. Unmarshaling any other value is
/// <c>TPM_RC_VALUE</c> (the table's own <c>#</c>).
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.4.4, Table 192.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmiAlgRsaDecrypt
{
    /// <summary>
    /// Gets the raw algorithm selector.
    /// </summary>
    public TpmAlgIdConstants Value { get; }

    /// <summary>
    /// Initializes a decryption-scheme selector from a raw value.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    public TpmiAlgRsaDecrypt(TpmAlgIdConstants value)
    {
        Value = value;
    }

    /// <summary>
    /// Gets whether this selector is <c>TPM_ALG_NULL</c>.
    /// </summary>
    public bool IsNull => Value == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Whether a raw algorithm value is one of the RSA decryption schemes this type admits.
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns><see langword="true"/> when <paramref name="value"/> is admitted.</returns>
    public static bool IsRsaDecryptScheme(TpmAlgIdConstants value, bool isNullAdmitted = false) => value switch
    {
        TpmAlgIdConstants.TPM_ALG_RSAES or
        TpmAlgIdConstants.TPM_ALG_OAEP => true,
        TpmAlgIdConstants.TPM_ALG_NULL => isNullAdmitted,
        TpmAlgIdConstants.TPM_ALG_ERROR => false,
        TpmAlgIdConstants.TPM_ALG_RSA => false,
        TpmAlgIdConstants.TPM_ALG_TDES => false,
        TpmAlgIdConstants.TPM_ALG_SHA => false,
        TpmAlgIdConstants.TPM_ALG_HMAC => false,
        TpmAlgIdConstants.TPM_ALG_AES => false,
        TpmAlgIdConstants.TPM_ALG_MGF1 => false,
        TpmAlgIdConstants.TPM_ALG_KEYEDHASH => false,
        TpmAlgIdConstants.TPM_ALG_XOR => false,
        TpmAlgIdConstants.TPM_ALG_SHA256 => false,
        TpmAlgIdConstants.TPM_ALG_SHA384 => false,
        TpmAlgIdConstants.TPM_ALG_SHA512 => false,
        TpmAlgIdConstants.TPM_ALG_SHA256_192 => false,
        TpmAlgIdConstants.TPM_ALG_SM3_256 => false,
        TpmAlgIdConstants.TPM_ALG_SM4 => false,
        TpmAlgIdConstants.TPM_ALG_RSASSA => false,
        TpmAlgIdConstants.TPM_ALG_RSAPSS => false,
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
        TpmAlgIdConstants.TPM_ALG_MLKEM => false,
        TpmAlgIdConstants.TPM_ALG_MLDSA => false,
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => false,
        _ => false
    };

    /// <summary>
    /// Parses a decryption-scheme selector from a TPM reader, validating it against the admitted set.
    /// </summary>
    /// <param name="reader">The reader positioned at the 2-octet selector.</param>
    /// <param name="isNullAdmitted">Whether <c>TPM_ALG_NULL</c> is also admitted.</param>
    /// <returns>The parsed selector.</returns>
    /// <exception cref="InvalidOperationException">The value is not an admitted RSA decryption scheme (<c>TPM_RC_VALUE</c>).</exception>
    public static TpmiAlgRsaDecrypt Parse(ref TpmReader reader, bool isNullAdmitted = false)
    {
        var value = (TpmAlgIdConstants)reader.ReadUInt16();
        if(!IsRsaDecryptScheme(value, isNullAdmitted))
        {
            throw new InvalidOperationException($"Invalid RSA decryption scheme 0x{(ushort)value:X4}. Expected TPM_ALG_RSAES or TPM_ALG_OAEP{(isNullAdmitted ? ", or TPM_ALG_NULL" : string.Empty)}.");
        }

        return new TpmiAlgRsaDecrypt(value);
    }

    /// <summary>
    /// Creates a decryption-scheme selector from a raw value without validation — for a value already known
    /// good (for example one retained from a validated command).
    /// </summary>
    /// <param name="value">The raw algorithm selector.</param>
    /// <returns>The selector.</returns>
    public static TpmiAlgRsaDecrypt FromValue(TpmAlgIdConstants value) => new(value);

    /// <summary>
    /// Writes this selector to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer) => writer.WriteUInt16((ushort)Value);

    /// <summary>
    /// The debugger's one-line rendering.
    /// </summary>
    private string DebuggerDisplay => $"TPMI_ALG_RSA_DECRYPT({Value})";
}
