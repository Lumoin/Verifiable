using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// TPM_ALG_ID constants (Table 11).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 11).
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1069:Enums values should not be duplicated", Justification = "TPM 2.0 specification allows duplicate values for compatibility and other reasons.")]
public enum TpmAlgIdConstants: ushort
{
    /// <summary>
    /// should not occur
    /// </summary>
    TPM_ALG_ERROR = 0x0000,

    /// <summary>
    /// the RSA algorithm
    /// </summary>
    TPM_ALG_RSA = 0x0001,

    /// <summary>
    /// Deprecated. See Part 18033-3 0.
    /// </summary>
    TPM_ALG_TDES = 0x0003,

    /// <summary>
    /// the SHA1 algorithm 10118-3 Deprecated. See Part 0.
    /// </summary>
    TPM_ALG_SHA = 0x0004,

    /// <summary>
    /// redefinition for 10118-3 documentation consistency Deprecated. See Part 0.
    /// </summary>
    TPM_ALG_SHA1 = 0x0004,

    /// <summary>
    /// Hash Message Authentication Code (HMAC) algorithm
    /// </summary>
    TPM_ALG_HMAC = 0x0005,

    /// <summary>
    /// the AES algorithm with 18033-3 various key sizes
    /// </summary>
    TPM_ALG_AES = 0x0006,

    /// <summary>
    /// Std hash-based 1363™-2000 mask-generation IEEE Std function 1363a™-2004
    /// </summary>
    TPM_ALG_MGF1 = 0x0007,

    /// <summary>
    /// an object type that may 2.0 library use XOR for encryption specification or an HMAC for signing and may also refer to a data object that is neither signing nor encrypting
    /// </summary>
    TPM_ALG_KEYEDHASH = 0x0008,

    /// <summary>
    /// the XOR encryption 2.0 library algorithm specification
    /// </summary>
    TPM_ALG_XOR = 0x000A,

    /// <summary>
    /// the SHA 256 algorithm 10118-3
    /// </summary>
    TPM_ALG_SHA256 = 0x000B,

    /// <summary>
    /// the SHA 384 algorithm 10118-3
    /// </summary>
    TPM_ALG_SHA384 = 0x000C,

    /// <summary>
    /// the SHA 512 algorithm 10118-3
    /// </summary>
    TPM_ALG_SHA512 = 0x000D,

    /// <summary>
    /// the most significant (i.e. 800-208 leftmost) 192 bits of the SHA-256 hash
    /// </summary>
    TPM_ALG_SHA256_192 = 0x000E,

    /// <summary>
    /// Null algorithm 2.0 library specification
    /// </summary>
    TPM_ALG_NULL = 0x0010,

    /// <summary>
    /// SM3 hash algorithm 10118-3:2018
    /// </summary>
    TPM_ALG_SM3_256 = 0x0012,

    /// <summary>
    /// GB/T SM4 symmetric block 32907-2016 cipher
    /// </summary>
    TPM_ALG_SM4 = 0x0013,

    /// <summary>
    /// a signature algorithm defined in clause 8.2 (RSASSA-PKCS1-v1_5)
    /// </summary>
    TPM_ALG_RSASSA = 0x0014,

    /// <summary>
    /// a padding algorithm defined in clause 7.2 (RSAES-PKCS1-v1_5)
    /// </summary>
    TPM_ALG_RSAES = 0x0015,

    /// <summary>
    /// a signature algorithm defined in clause 8.1 (RSASSA-PSS)
    /// </summary>
    TPM_ALG_RSAPSS = 0x0016,

    /// <summary>
    /// a padding algorithm defined in clause 7.1 (RSAES_OAEP)
    /// </summary>
    TPM_ALG_OAEP = 0x0017,

    /// <summary>
    /// signature algorithm 14888-3 using elliptic curve cryptography (ECC) (Non-deterministic ECDSA)
    /// </summary>
    TPM_ALG_ECDSA = 0x0018,

    /// <summary>
    /// secret sharing using 800-56A ECC IETF RFC 7748 Based on context, this can be either One-Pass Diffie-Hellman, C(1, 1, ECC CDH) defined in
    /// </summary>
    TPM_ALG_ECDH = 0x0019,

    /// <summary>
    /// elliptic-curve based, 2.0 library anonymous signing specification scheme
    /// </summary>
    TPM_ALG_ECDAA = 0x001A,

    /// <summary>
    /// GB/T SM2 - depending on M 32918.1-2016 context, either an GB/T elliptic-curve based 32918.2-2016 signature algorithm, an GB/T encryption scheme or a 32918.3-2016 key exchange protocol GB/T 32918.4-2016 GB/T 32918.5-2017
    /// </summary>
    TPM_ALG_SM2 = 0x001B,

    /// <summary>
    /// elliptic-curve based 2.0 library Schnorr signature specification
    /// </summary>
    TPM_ALG_ECSCHNORR = 0x001C,

    /// <summary>
    /// two-phase elliptic-curve 800-56A key exchange – C(2, 2, ECC MQV) clause
    /// </summary>
    TPM_ALG_ECMQV = 0x001D,

    /// <summary>
    /// concatenation key 800-56A derivation function (approved alternative 1) clause 5.8.1
    /// </summary>
    TPM_ALG_KDF1_SP800_56A = 0x0020,

    /// <summary>
    /// Std key derivation function 1363a-2004 KDF2 clause 13.2
    /// </summary>
    TPM_ALG_KDF2 = 0x0021,

    /// <summary>
    /// a key derivation method 800-108 clause 5.1 KDF in Counter Mode
    /// </summary>
    TPM_ALG_KDF1_SP800_108 = 0x0022,

    /// <summary>
    /// prime field ECC 15946-1
    /// </summary>
    TPM_ALG_ECC = 0x0023,

    /// <summary>
    /// the object type for a 2.0 library symmetric block cipher specification
    /// </summary>
    TPM_ALG_SYMCIPHER = 0x0025,

    /// <summary>
    /// Camellia is a symmetric 18033-3 block cipher. The Camellia algorithm has various key sizes.
    /// </summary>
    TPM_ALG_CAMELLIA = 0x0026,

    /// <summary>
    /// Hash algorithm 10118-3 producing a 256 bit digest
    /// </summary>
    TPM_ALG_SHA3_256 = 0x0027,

    /// <summary>
    /// Hash algorithm 10118-3 producing a 384 bit digest
    /// </summary>
    TPM_ALG_SHA3_384 = 0x0028,

    /// <summary>
    /// Hash algorithm 10118-3 producing a 512 bit digest
    /// </summary>
    TPM_ALG_SHA3_512 = 0x0029,

    /// <summary>
    /// Extendable-output 10118-3 function providing up to 128 bits of collision and preimage resistance
    /// </summary>
    TPM_ALG_SHAKE128 = 0x002A,

    /// <summary>
    /// Extendable-output 10118-3 function providing up to 256 bits of collision and preimage resistance
    /// </summary>
    TPM_ALG_SHAKE256 = 0x002B,

    /// <summary>
    /// the first 192 bits of 800-208 SHAKE256 output
    /// </summary>
    TPM_ALG_SHAKE256_192 = 0x002C,

    /// <summary>
    /// the first 256 bits of 800-208 SHAKE256 output
    /// </summary>
    TPM_ALG_SHAKE256_256 = 0x002D,

    /// <summary>
    /// the first 512 bits of SHAKE256 output
    /// </summary>
    TPM_ALG_SHAKE256_512 = 0x002E,

    /// <summary>
    /// Block Cipher-based 9797-1:2011 Message Authentication Code (CMAC) "Algorithm 5" in ISO/IEC 9797-1:2011
    /// </summary>
    TPM_ALG_CMAC = 0x003F,

    /// <summary>
    /// Counter mode - if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
    /// </summary>
    TPM_ALG_CTR = 0x0040,

    /// <summary>
    /// Output Feedback mode - if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
    /// </summary>
    TPM_ALG_OFB = 0x0041,

    /// <summary>
    /// Cipher Block Chaining mode - if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
    /// </summary>
    TPM_ALG_CBC = 0x0042,

    /// <summary>
    /// Cipher Feedback mode - if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode.
    /// </summary>
    TPM_ALG_CFB = 0x0043,

    /// <summary>
    /// Electronic Codebook mode - if implemented, all symmetric block ciphers (S type) implemented shall be capable of using this mode. Note: This mode is not recommended unless the key is frequently rotated, such as in video codecs.
    /// </summary>
    TPM_ALG_ECB = 0x0044,

    /// <summary>
    /// Counter with 800-38C Cipher Block Chaining-Message Authentication Code (CCM)
    /// </summary>
    TPM_ALG_CCM = 0x0050,

    /// <summary>
    /// Galois/Counter Mode 800-38D (GCM)
    /// </summary>
    TPM_ALG_GCM = 0x0051,

    /// <summary>
    /// Key Wrap (KW) 800-38F
    /// </summary>
    TPM_ALG_KW = 0x0052,

    /// <summary>
    /// Key Wrap with 800-38F Padding (KWP)
    /// </summary>
    TPM_ALG_KWP = 0x0053,

    /// <summary>
    /// Authenticated-Encryption Mode
    /// </summary>
    TPM_ALG_EAX = 0x0054,

    /// <summary>
    /// Edwards-curve Digital Signature Algorithm (PureEdDSA) Note: EdDSA requires Twisted Edwards curves.
    /// </summary>
    TPM_ALG_EDDSA = 0x0060,

    /// <summary>
    /// Edwards-curve Digital Signature Algorithm (HashEdDSA) Note: EdDSA requires Twisted Edwards curves.
    /// </summary>
    TPM_ALG_EDDSA_PH = 0x0061,

    /// <summary>
    /// Leighton-Micali 800-208 Signatures (LMS)
    /// </summary>
    TPM_ALG_LMS = 0x0070,

    /// <summary>
    /// eXtended Merkle 800-208 Signature Scheme (XMSS) (single tree)
    /// </summary>
    TPM_ALG_XMSS = 0x0071,

    /// <summary>
    /// any keyed XOF
    /// </summary>
    TPM_ALG_KEYEDXOF = 0x0080,

    /// <summary>
    /// a keyed XOF providing 800-185 128-bit security strength
    /// </summary>
    TPM_ALG_KMACXOF128 = 0x0081,

    /// <summary>
    /// a keyed XOF providing 800-185 256-bit security strength
    /// </summary>
    TPM_ALG_KMACXOF256 = 0x0082,

    /// <summary>
    /// a variable-length 800-185 MAC providing 128-bit security strength
    /// </summary>
    TPM_ALG_KMAC128 = 0x0090,

    /// <summary>
    /// a variable-length 800-185 MAC providing 256-bit security strength
    /// </summary>
    TPM_ALG_KMAC256 = 0x0091,

    /// <summary>
    /// Module-Lattice-Based Key-Encapsulation Mechanism (NIST FIPS 203).
    /// </summary>
    /// <remarks>
    /// Post-quantum key encapsulation mechanism. Used for restricted decryption keys.
    /// Supports TPM2_Encapsulate() and TPM2_Decapsulate() operations.
    /// </remarks>
    TPM_ALG_MLKEM = 0x00A0,

    /// <summary>
    /// Module-Lattice-Based Digital Signature Algorithm (NIST FIPS 204).
    /// </summary>
    /// <remarks>
    /// Post-quantum digital signature algorithm. Used for signing keys.
    /// Supports sequence-based signing via TPM2_SignSequenceComplete() and
    /// TPM2_VerifySequenceComplete(). May also support TPM2_SignDigest() and
    /// TPM2_VerifyDigestSignature() if allowExternalMu is TRUE.
    /// </remarks>
    TPM_ALG_MLDSA = 0x00A1,

    /// <summary>
    /// Pre-Hash Module-Lattice-Based Digital Signature Algorithm (NIST FIPS 204).
    /// </summary>
    /// <remarks>
    /// Pre-hash variant of ML-DSA where the message is hashed before signing.
    /// The hash algorithm is specified in the key parameters.
    /// </remarks>
    TPM_ALG_HASH_MLDSA = 0x00A2
}