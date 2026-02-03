namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// Extension methods for <see cref="TpmAlgIdConstants"/>.
/// </summary>
public static class TpmAlgIdExtensions
{
    /// <summary>
    /// Gets the human-readable name for an algorithm.
    /// </summary>
    public static string GetName(this TpmAlgIdConstants algorithm)
    {
        return algorithm switch
        {
            TpmAlgIdConstants.TPM_ALG_ERROR => "ERROR",
            TpmAlgIdConstants.TPM_ALG_RSA => "RSA",
            TpmAlgIdConstants.TPM_ALG_TDES => "TDES",
            TpmAlgIdConstants.TPM_ALG_SHA1 => "SHA1",
            TpmAlgIdConstants.TPM_ALG_HMAC => "HMAC",
            TpmAlgIdConstants.TPM_ALG_AES => "AES",
            TpmAlgIdConstants.TPM_ALG_MGF1 => "MGF1",
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => "KEYEDHASH",
            TpmAlgIdConstants.TPM_ALG_XOR => "XOR",
            TpmAlgIdConstants.TPM_ALG_SHA256 => "SHA256",
            TpmAlgIdConstants.TPM_ALG_SHA384 => "SHA384",
            TpmAlgIdConstants.TPM_ALG_SHA512 => "SHA512",
            TpmAlgIdConstants.TPM_ALG_SHA256_192 => "SHA256_192",
            TpmAlgIdConstants.TPM_ALG_NULL => "NULL",
            TpmAlgIdConstants.TPM_ALG_SM3_256 => "SM3_256",
            TpmAlgIdConstants.TPM_ALG_SM4 => "SM4",
            TpmAlgIdConstants.TPM_ALG_RSASSA => "RSASSA",
            TpmAlgIdConstants.TPM_ALG_RSAES => "RSAES",
            TpmAlgIdConstants.TPM_ALG_RSAPSS => "RSAPSS",
            TpmAlgIdConstants.TPM_ALG_OAEP => "OAEP",
            TpmAlgIdConstants.TPM_ALG_ECDSA => "ECDSA",
            TpmAlgIdConstants.TPM_ALG_ECDH => "ECDH",
            TpmAlgIdConstants.TPM_ALG_ECDAA => "ECDAA",
            TpmAlgIdConstants.TPM_ALG_SM2 => "SM2",
            TpmAlgIdConstants.TPM_ALG_ECSCHNORR => "ECSCHNORR",
            TpmAlgIdConstants.TPM_ALG_ECMQV => "ECMQV",
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A => "KDF1_SP800_56A",
            TpmAlgIdConstants.TPM_ALG_KDF2 => "KDF2",
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 => "KDF1_SP800_108",
            TpmAlgIdConstants.TPM_ALG_ECC => "ECC",
            TpmAlgIdConstants.TPM_ALG_SYMCIPHER => "SYMCIPHER",
            TpmAlgIdConstants.TPM_ALG_CAMELLIA => "CAMELLIA",
            TpmAlgIdConstants.TPM_ALG_SHA3_256 => "SHA3_256",
            TpmAlgIdConstants.TPM_ALG_SHA3_384 => "SHA3_384",
            TpmAlgIdConstants.TPM_ALG_SHA3_512 => "SHA3_512",
            TpmAlgIdConstants.TPM_ALG_SHAKE128 => "SHAKE128",
            TpmAlgIdConstants.TPM_ALG_SHAKE256 => "SHAKE256",
            TpmAlgIdConstants.TPM_ALG_SHAKE256_192 => "SHAKE256_192",
            TpmAlgIdConstants.TPM_ALG_SHAKE256_256 => "SHAKE256_256",
            TpmAlgIdConstants.TPM_ALG_SHAKE256_512 => "SHAKE256_512",
            TpmAlgIdConstants.TPM_ALG_CMAC => "CMAC",
            TpmAlgIdConstants.TPM_ALG_CTR => "CTR",
            TpmAlgIdConstants.TPM_ALG_OFB => "OFB",
            TpmAlgIdConstants.TPM_ALG_CBC => "CBC",
            TpmAlgIdConstants.TPM_ALG_CFB => "CFB",
            TpmAlgIdConstants.TPM_ALG_ECB => "ECB",
            TpmAlgIdConstants.TPM_ALG_CCM => "CCM",
            TpmAlgIdConstants.TPM_ALG_GCM => "GCM",
            TpmAlgIdConstants.TPM_ALG_KW => "KW",
            TpmAlgIdConstants.TPM_ALG_KWP => "KWP",
            TpmAlgIdConstants.TPM_ALG_EAX => "EAX",
            TpmAlgIdConstants.TPM_ALG_EDDSA => "EDDSA",
            TpmAlgIdConstants.TPM_ALG_EDDSA_PH => "EDDSA_PH",
            TpmAlgIdConstants.TPM_ALG_LMS => "LMS",
            TpmAlgIdConstants.TPM_ALG_XMSS => "XMSS",
            TpmAlgIdConstants.TPM_ALG_KEYEDXOF => "KEYEDXOF",
            TpmAlgIdConstants.TPM_ALG_KMACXOF128 => "KMACXOF128",
            TpmAlgIdConstants.TPM_ALG_KMACXOF256 => "KMACXOF256",
            TpmAlgIdConstants.TPM_ALG_KMAC128 => "KMAC128",
            TpmAlgIdConstants.TPM_ALG_KMAC256 => "KMAC256",
            TpmAlgIdConstants.TPM_ALG_MLKEM => "MLKEM",
            TpmAlgIdConstants.TPM_ALG_MLDSA => "MLDSA",
            TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => "HASH_MLDSA",
            _ => $"ALG_0x{(ushort)algorithm:X4}"
        };
    }

    /// <summary>
    /// Gets the digest size in bytes for a hash algorithm, or null if not a hash algorithm.
    /// </summary>
    public static int? GetDigestSize(this TpmAlgIdConstants algorithm)
    {
        return algorithm switch
        {
            TpmAlgIdConstants.TPM_ALG_SHA1 => 20,
            TpmAlgIdConstants.TPM_ALG_SHA256 => 32,
            TpmAlgIdConstants.TPM_ALG_SHA384 => 48,
            TpmAlgIdConstants.TPM_ALG_SHA512 => 64,
            TpmAlgIdConstants.TPM_ALG_SHA256_192 => 24,
            TpmAlgIdConstants.TPM_ALG_SM3_256 => 32,
            TpmAlgIdConstants.TPM_ALG_SHA3_256 => 32,
            TpmAlgIdConstants.TPM_ALG_SHA3_384 => 48,
            TpmAlgIdConstants.TPM_ALG_SHA3_512 => 64,
            TpmAlgIdConstants.TPM_ALG_SHAKE256_192 => 24,
            TpmAlgIdConstants.TPM_ALG_SHAKE256_256 => 32,
            TpmAlgIdConstants.TPM_ALG_SHAKE256_512 => 64,
            _ => null
        };
    }

    /// <summary>
    /// Gets whether the algorithm is a hash algorithm.
    /// </summary>
    public static bool IsHashAlgorithm(this TpmAlgIdConstants algorithm)
    {
        return algorithm.GetDigestSize() is not null;
    }
}