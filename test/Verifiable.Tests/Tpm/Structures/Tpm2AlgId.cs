namespace Verifiable.Tpm.Structures
{
    /// <summary>
    /// Represents the TPM 2.0 algorithm identifier constants as specified in the TPM 2.0 specification.
    /// </summary>
    /// <remarks>
    /// For information see
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf"/>
    /// Trusted Platform Module Library Part 2: Structures Family "2.0" Level 00 Revision 01.38 6.3 TPM2_ALG_ID Constants and
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TSS_Overview_Common_v1_r10_pub09232021.pdf">
    /// TCG TSS 2.0 Overview and Common Structures Specification Version 1.0 Revision 10 Table 9 - Definition of (UINT16) TPM2_ALG_ID Constants.</see>
    /// </remarks>
    public enum Tpm2AlgId: ushort
    {
        /// <summary>Algorithm identifier error value.</summary>
        Error = 0x0000,

        /// <summary>RSA algorithm identifier.</summary>
        Rsa = 0x0001,

        /// <summary>TDES algorithm identifier.</summary>
        Tdes = 0x0003,

        /// <summary>SHA algorithm identifier.</summary>
        Sha = 0x0004,

        /// <summary>SHA-1 algorithm identifier.</summary>
        Sha1 = 0x0004,

        /// <summary>HMAC algorithm identifier.</summary>
        Hmac = 0x0005,

        /// <summary>AES algorithm identifier.</summary>
        Aes = 0x0006,

        /// <summary>MGF1 algorithm identifier.</summary>
        Mgf1 = 0x0007,

        /// <summary>KeyedHash algorithm identifier.</summary>
        KeyedHash = 0x0008,

        /// <summary>XOR algorithm identifier.</summary>
        Xor = 0x000A,

        /// <summary>SHA-256 algorithm identifier.</summary>
        Sha256 = 0x000B,

        /// <summary>SHA-384 algorithm identifier.</summary>
        Sha384 = 0x000C,

        /// <summary>SHA-512 algorithm identifier.</summary>
        Sha512 = 0x000D,

        /// <summary>Null algorithm identifier.</summary>
        Null = 0x0010,

        /// <summary>SM3-256 algorithm identifier.</summary>
        Sm3_256 = 0x0012,

        /// <summary>SM4 algorithm identifier.</summary>
        Sm4 = 0x0013,

        /// <summary>RSASSA algorithm identifier.</summary>
        Rsassa = 0x0014,

        /// <summary>RSAES algorithm identifier.</summary>
        Rsaes = 0x0015,

        /// <summary>RSAPSS algorithm identifier.</summary>
        Rsapss = 0x0016,

        /// <summary>OAEP algorithm identifier.</summary>
        Oaep = 0x0017,

        /// <summary>ECDSA algorithm identifier.</summary>
        Ecdsa = 0x0018,

        /// <summary>ECDH algorithm identifier.</summary>
        Ecdh = 0x0019,

        /// <summary>ECDAA algorithm identifier.</summary>
        Ecdaa = 0x001A,

        /// <summary>SM2 algorithm identifier.</summary>
        Sm2 = 0x001B,

        /// <summary>ECSchnorr algorithm identifier.</summary>
        EcSchnorr = 0x001C,

        /// <summary>ECMQV algorithm identifier.</summary>
        Ecmqv = 0x001D,

        /// <summary>KDF1-SP800-56A algorithm identifier.</summary>
        Kdf1Sp800_56A = 0x0020,

        /// <summary>KDF2 algorithm identifier.</summary>
        Kdf2 = 0x0021,

        /// <summary>KDF1-SP800-108 algorithm identifier.</summary>
        Kdf1Sp800_108 = 0x0022,

        /// <summary>ECC algorithm identifier.</summary>
        Ecc = 0x0023,

        /// <summary>Symmetric cipher algorithm identifier.</summary>
        SymCipher = 0x0025,

        // <summary>Camellia algorithm identifier.</summary>
        Camellia = 0x0026,

        /// <summary>SHA3-256 algorithm identifier.</summary>
        Sha3_256 = 0x0027,

        /// <summary>SHA3-384 algorithm identifier.</summary>
        Sha3_384 = 0x0028,

        /// <summary>SHA3-512 algorithm identifier.</summary>
        Sha3_512 = 0x0029,

        /// <summary>CTR algorithm identifier.</summary>
        Ctr = 0x0040,

        /// <summary>OFB algorithm identifier.</summary>
        Ofb = 0x0041,

        /// <summary>CBC algorithm identifier.</summary>
        Cbc = 0x0042,

        /// <summary>CFB algorithm identifier.</summary>
        Cfb = 0x0043,

        /// <summary>ECB algorithm identifier.</summary>
        Ecb = 0x0044
    }
}
