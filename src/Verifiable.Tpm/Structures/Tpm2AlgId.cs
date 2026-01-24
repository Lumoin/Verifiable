namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM 2.0 algorithm identifiers (TPM_ALG_ID).
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 6.4 - TPM_ALG_ID.
/// </para>
/// </remarks>
public enum Tpm2AlgId: ushort
{
    /// <summary>
    /// TPM_ALG_ERROR: Should not occur.
    /// </summary>
    TPM_ALG_ERROR = 0x0000,

    /// <summary>
    /// TPM_ALG_RSA: RSA key algorithm.
    /// </summary>
    TPM_ALG_RSA = 0x0001,

    /// <summary>
    /// TPM_ALG_TDES: Triple DES symmetric algorithm. Deprecated.
    /// </summary>
    TPM_ALG_TDES = 0x0003,

    /// <summary>
    /// TPM_ALG_SHA1: SHA-1 hash algorithm.
    /// </summary>
    TPM_ALG_SHA1 = 0x0004,

    /// <summary>
    /// TPM_ALG_HMAC: HMAC algorithm.
    /// </summary>
    TPM_ALG_HMAC = 0x0005,

    /// <summary>
    /// TPM_ALG_AES: AES symmetric block cipher algorithm.
    /// </summary>
    TPM_ALG_AES = 0x0006,

    /// <summary>
    /// TPM_ALG_MGF1: Mask Generation Function using a hash algorithm.
    /// </summary>
    TPM_ALG_MGF1 = 0x0007,

    /// <summary>
    /// TPM_ALG_KEYEDHASH: Keyed hash object type for HMAC and XOR obfuscation.
    /// </summary>
    TPM_ALG_KEYEDHASH = 0x0008,

    /// <summary>
    /// TPM_ALG_XOR: XOR obfuscation using a hash algorithm.
    /// </summary>
    TPM_ALG_XOR = 0x000A,

    /// <summary>
    /// TPM_ALG_SHA256: SHA-256 hash algorithm.
    /// </summary>
    TPM_ALG_SHA256 = 0x000B,

    /// <summary>
    /// TPM_ALG_SHA384: SHA-384 hash algorithm.
    /// </summary>
    TPM_ALG_SHA384 = 0x000C,

    /// <summary>
    /// TPM_ALG_SHA512: SHA-512 hash algorithm.
    /// </summary>
    TPM_ALG_SHA512 = 0x000D,

    /// <summary>
    /// TPM_ALG_NULL: Null algorithm indicator.
    /// </summary>
    TPM_ALG_NULL = 0x0010,

    /// <summary>
    /// TPM_ALG_SM3_256: SM3 256-bit hash algorithm (Chinese national standard).
    /// </summary>
    TPM_ALG_SM3_256 = 0x0012,

    /// <summary>
    /// TPM_ALG_SM4: SM4 128-bit block cipher algorithm (Chinese national standard).
    /// </summary>
    TPM_ALG_SM4 = 0x0013,

    /// <summary>
    /// TPM_ALG_RSASSA: RSASSA-PKCS1-v1_5 signature algorithm.
    /// </summary>
    TPM_ALG_RSASSA = 0x0014,

    /// <summary>
    /// TPM_ALG_RSAES: RSAES-PKCS1-v1_5 encryption algorithm.
    /// </summary>
    TPM_ALG_RSAES = 0x0015,

    /// <summary>
    /// TPM_ALG_RSAPSS: RSASSA-PSS signature algorithm.
    /// </summary>
    TPM_ALG_RSAPSS = 0x0016,

    /// <summary>
    /// TPM_ALG_OAEP: RSA-OAEP encryption algorithm.
    /// </summary>
    TPM_ALG_OAEP = 0x0017,

    /// <summary>
    /// TPM_ALG_ECDSA: Elliptic Curve Digital Signature Algorithm.
    /// </summary>
    TPM_ALG_ECDSA = 0x0018,

    /// <summary>
    /// TPM_ALG_ECDH: Elliptic Curve Diffie-Hellman key exchange.
    /// </summary>
    TPM_ALG_ECDH = 0x0019,

    /// <summary>
    /// TPM_ALG_ECDAA: Elliptic Curve Direct Anonymous Attestation.
    /// </summary>
    TPM_ALG_ECDAA = 0x001A,

    /// <summary>
    /// TPM_ALG_SM2: SM2 elliptic curve algorithm (Chinese national standard).
    /// </summary>
    TPM_ALG_SM2 = 0x001B,

    /// <summary>
    /// TPM_ALG_ECSCHNORR: Elliptic Curve Schnorr signature algorithm.
    /// </summary>
    TPM_ALG_ECSCHNORR = 0x001C,

    /// <summary>
    /// TPM_ALG_ECMQV: Elliptic Curve Menezes-Qu-Vanstone key exchange.
    /// </summary>
    TPM_ALG_ECMQV = 0x001D,

    /// <summary>
    /// TPM_ALG_KDF1_SP800_56A: Key derivation using SP800-56A.
    /// </summary>
    TPM_ALG_KDF1_SP800_56A = 0x0020,

    /// <summary>
    /// TPM_ALG_KDF2: Key derivation function from IEEE Std 1363a-2004.
    /// </summary>
    TPM_ALG_KDF2 = 0x0021,

    /// <summary>
    /// TPM_ALG_KDF1_SP800_108: Key derivation using SP800-108 (counter mode).
    /// </summary>
    TPM_ALG_KDF1_SP800_108 = 0x0022,

    /// <summary>
    /// TPM_ALG_ECC: Prime field ECC key algorithm.
    /// </summary>
    TPM_ALG_ECC = 0x0023,

    /// <summary>
    /// TPM_ALG_SYMCIPHER: Symmetric block cipher object type.
    /// </summary>
    TPM_ALG_SYMCIPHER = 0x0025,

    /// <summary>
    /// TPM_ALG_CAMELLIA: Camellia symmetric block cipher algorithm.
    /// </summary>
    TPM_ALG_CAMELLIA = 0x0026,

    /// <summary>
    /// TPM_ALG_SHA3_256: SHA3-256 hash algorithm.
    /// </summary>
    TPM_ALG_SHA3_256 = 0x0027,

    /// <summary>
    /// TPM_ALG_SHA3_384: SHA3-384 hash algorithm.
    /// </summary>
    TPM_ALG_SHA3_384 = 0x0028,

    /// <summary>
    /// TPM_ALG_SHA3_512: SHA3-512 hash algorithm.
    /// </summary>
    TPM_ALG_SHA3_512 = 0x0029,

    /// <summary>
    /// TPM_ALG_CTR: Counter mode symmetric cipher.
    /// </summary>
    TPM_ALG_CTR = 0x0040,

    /// <summary>
    /// TPM_ALG_OFB: Output Feedback mode symmetric cipher.
    /// </summary>
    TPM_ALG_OFB = 0x0041,

    /// <summary>
    /// TPM_ALG_CBC: Cipher Block Chaining mode symmetric cipher.
    /// </summary>
    TPM_ALG_CBC = 0x0042,

    /// <summary>
    /// TPM_ALG_CFB: Cipher Feedback mode symmetric cipher.
    /// </summary>
    TPM_ALG_CFB = 0x0043,

    /// <summary>
    /// TPM_ALG_ECB: Electronic Codebook mode symmetric cipher.
    /// </summary>
    TPM_ALG_ECB = 0x0044
}