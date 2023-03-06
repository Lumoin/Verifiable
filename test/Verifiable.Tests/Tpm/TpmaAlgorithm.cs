using System;

namespace Verifiable.Tpm
{
    /// <summary>
    /// Represents the algorithm attributes as specified in the TPM 2.0 specification.
    /// </summary>
    /// <remarks>
    /// For information see
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf"/>
    /// Trusted Platform Module Library Part 2: Structures Family "2.0" Level 00 Revision 01.38 8.2 TPMA_ALGORITHM and 
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TSS_Overview_Common_v1_r10_pub09232021.pdf">
    /// TCG TSS 2.0 Overview and Common Structures Specification Version 1.0 Revision 10 Table 30 - Definition of (UINT32) TPMA_ALGORITHM Bits.</see>
    /// </remarks>.
    [Flags]
    public enum TpmaAlgorithm: uint
    {
        /// <summary>
        /// The algorithm is an asymmetric algorithm.
        /// </summary>
        Asymmetric = 0x00000001,

        /// <summary>
        /// The algorithm is a symmetric algorithm.
        /// </summary>
        Symmetric = 0x00000002,

        /// <summary>
        /// The algorithm is a hash algorithm.
        /// </summary>
        Hash = 0x00000004,

        /// <summary>
        /// The algorithm is an object algorithm.
        /// </summary>
        Object = 0x00000008,

        /// <summary>
        /// Reserved bits.
        /// </summary>
        Reserved1Mask = 0x000000F0,

        /// <summary>
        /// The algorithm is a signing algorithm.
        /// </summary>
        Signing = 0x00000100,

        /// <summary>
        /// The algorithm is an encrypting algorithm.
        /// </summary>
        Encrypting = 0x00000200,

        /// <summary>
        /// The algorithm is a method algorithm.
        /// </summary>
        Method = 0x00000400,

        /// <summary>
        /// Reserved bits.
        /// </summary>
        Reserved2Mask = 0xFFFFF800
    }
}
