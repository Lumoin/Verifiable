using Verifiable.Tpm;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Structures
{
    /// <summary>
    /// Contains various constants used in TPM 2.0 as defined by the specification.
    /// </summary>
    /// <remarks>
    /// The constants in this class are derived from the TPM 2.0 specification, which can be found at:
    /// <see href="https://trustedcomputinggroup.org/wp-content/uploads/TSS_Overview_Common_v1_r10_pub09232021.pdf">
    /// TCG TSS 2.0 Overview and Common Structures Specification Version 1.0 Revision 10 September 23, 2021 
    /// tss2_tpm2_types.h ABI Constants</see>.
    /// </remarks>
    public static class Tpm2Constants
    {
        //Digest sizes of common algorithms.
        public const int ShaDigestSize = 20;
        public const int Sha1DigestSize = 20;
        public const int Sha256DigestSize = 32;
        public const int Sha384DigestSize = 48;
        public const int Sha512DigestSize = 64;
        public const int Sm3_256DigestSize = 32;

        //TSS Working Group chosen constants.
        public const int NumPcrBanks = 16;
        public const int MaxDigestBuffer = 1024;
        public const int MaxNvBufferSize = 2048;
        public const int MaxPcrs = 32;
        public const int MaxAlgListSize = 128;
        public const int MaxCapCc = 256;
        public const int MaxCapBuffer = 1024;
        public const int MaxContextSize = 5120;

        //Cryptographic algorithm parameters.
        public const int MaxSymBlockSize = 16;
        public const int MaxSymData = 256;
        public const int MaxEccKeyBytes = 128;
        public const int MaxSymKeyBytes = 32;
        public const int MaxRsaKeyBytes = 512;

        // Derived constants and generic TPM constants
        public const int LabelMaxBuffer = 32;
        public const int PcrSelectMax = (MaxPcrs + 7) / 8;
        public const int MaxCapHandles = (MaxCapBuffer - sizeof(uint) - sizeof(uint)) / sizeof(uint);

        //sizeof(TpmsAlgProperty) = sizeof(TpmsAlgProperty.Tpm2AlgId) + sizeof(TpmsAlgProperty.TpmaAlgorithm).
        public const int MaxCapAlgs = (MaxCapBuffer - sizeof(uint) - sizeof(uint)) / (sizeof(Tpm2AlgId) + sizeof(TpmaAlgorithm));

        /*        
        public const int MaxTpmProperties = (MaxCapBuffer - sizeof(uint) - sizeof(uint)) / sizeof(TpmsTaggedProperty);
        public const int MaxPcrProperties = (MaxCapBuffer - sizeof(uint) - sizeof(uint)) / sizeof(TpmsTaggedPcrSelect);
        public const int MaxEccCurves = (MaxCapBuffer - sizeof(uint) - sizeof(uint)) / sizeof(Tpm2EccCurve);
        public const int MaxTaggedPolicies = (MaxCapBuffer - sizeof(uint) - sizeof(uint)) / sizeof(TpmsTaggedPolicy);
        public const int MaxActData = (MaxCapBuffer - sizeof(uint) - sizeof(uint)) / sizeof(TpmsActData);
        public const int PrivateVendorSpecificBytes = (MaxRsaKeyBytes / 2) * (3 + 2);*/
    }
}
