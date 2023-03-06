namespace Verifiable.Tpm
{
    //These constants are from TCG TSS 2.0 Overview and Common Structures Specification
    //at https://trustedcomputinggroup.org/wp-content/uploads/TCG_TSS_2.0_r1p04_pub.pdf
    //https://trustedcomputinggroup.org/resource/tpm-library-specification/

    public enum TPM2_CAP: uint
    {
        FIRST = 0x00000000,
        ALGS = 0x00000000,
        HANDLES = 0x00000001,
        COMMANDS = 0x00000002,
        PP_COMMANDS = 0x00000003,
        AUDIT_COMMANDS = 0x00000004,
        PCRS = 0x00000005,
        TPM_PROPERTIES = 0x00000006,
        PCR_PROPERTIES = 0x00000007,
        ECC_CURVES = 0x00000008,
        AUTH_POLICIES = 0x00000009,
        ACT = 0x0000000A,
        LAST = 0x0000000A,
        VENDOR_PROPERTY = 0x00000100
    }


    public enum TPM_PT_PCR: uint
    {
        TPM_PT_PCR_COUNT = 0x00000000,
        TPM_PT_PCR_SELECT_MIN = 0x00000001,
        TPM_PT_PCR_SELECT_MAX = 0x00000002
    }


    public enum TPM_PT: uint
    {
        TPM_PT_FAMILY_INDICATOR = 0x100,
        TPM_PT_LEVEL = 0x101,
        TPM_PT_REVISION = 0x102,
        TPM_PT_DAY_OF_YEAR = 0x103,
        TPM_PT_YEAR = 0x104,
        TPM_PT_MANUFACTURER = 0x105,
        TPM_PT_VENDOR_STRING_1 = 0x106,
        TPM_PT_VENDOR_STRING_2 = 0x107,
        TPM_PT_VENDOR_STRING_3 = 0x108,
        TPM_PT_VENDOR_STRING_4 = 0x109,
        TPM_PT_VENDOR_TPM_TYPE = 0x10A,
        TPM_PT_FIRMWARE_VERSION_1 = 0x110,
        TPM_PT_FIRMWARE_VERSION_2 = 0x111
    }


    public enum TPM_SU: ushort
    {
        TPM_SU_CLEAR = 0x0000,
        TPM_SU_STATE = 0x0001
    }

    public static class TpmAttributes
    {
        public const uint TPMA_NV_PPWRITE = (1U << 0);
        public const uint TPMA_NV_OWNERWRITE = (1U << 1);
        public const uint TPMA_NV_AUTHWRITE = (1U << 2);
        public const uint TPMA_NV_POLICYWRITE = (1U << 3);
        public const uint TPMA_NV_COUNTER = (1U << 4);
        public const uint TPMA_NV_BITS = (1U << 5);
        public const uint TPMA_NV_EXTEND = (1U << 6);
        public const uint TPMA_NV_POLICY_DELETE = (1U << 10);
        public const uint TPMA_NV_WRITELOCKED = (1U << 11);
        public const uint TPMA_NV_WRITEALL = (1U << 12);
        public const uint TPMA_NV_WRITEDEFINE = (1U << 13);
        public const uint TPMA_NV_WRITE_STCLEAR = (1U << 14);
        public const uint TPMA_NV_GLOBALLOCK = (1U << 15);
        public const uint TPMA_NV_PPREAD = (1U << 16);
        public const uint TPMA_NV_OWNERREAD = (1U << 17);
        public const uint TPMA_NV_AUTHREAD = (1U << 18);
        public const uint TPMA_NV_POLICYREAD = (1U << 19);
        public const uint TPMA_NV_NO_DA = (1U << 25);
        public const uint TPMA_NV_ORDERLY = (1U << 26);
        public const uint TPMA_NV_CLEAR_STCLEAR = (1U << 27);
        public const uint TPMA_NV_READLOCKED = (1U << 28);
        public const uint TPMA_NV_WRITTEN = (1U << 29);
        public const uint TPMA_NV_PLATFORMCREATE = (1U << 30);
        public const uint TPMA_NV_READ_STCLEAR = (1U << 31);

        public const uint TPMA_NV_MASK_READ = (TPMA_NV_PPREAD | TPMA_NV_OWNERREAD |
                                               TPMA_NV_AUTHREAD | TPMA_NV_POLICYREAD);
        public const uint TPMA_NV_MASK_WRITE = (TPMA_NV_PPWRITE | TPMA_NV_OWNERWRITE |
                                                TPMA_NV_AUTHWRITE | TPMA_NV_POLICYWRITE);
    }

    public static class TpmConstants2Temp
    {
        public const uint TPM_BUFFER_SIZE = 256;
        // Tpm2 command tags.
        public const ushort TPM_ST_NO_SESSIONS = 0x8001;
        public const ushort TPM_ST_SESSIONS = 0x8002;
        // TPM2 command codes.
        public const uint TPM2_Hierarchy_Control = 0x00000121;
        public const uint TPM2_NV_UndefineSpace = 0x00000122;
        public const uint TPM2_Clear = 0x00000126;
        public const uint TPM2_NV_DefineSpace = 0x0000012A;
        public const uint TPM2_NV_Write = 0x00000137;
        public const uint TPM2_NV_WriteLock = 0x00000138;
        public const uint TPM2_SelfTest = 0x00000143;
        public const uint TPM2_Startup = 0x00000144;
        public const uint TPM2_Shutdown = 0x00000145;
        public const uint TPM2_NV_Read = 0x0000014E;
        public const uint TPM2_NV_ReadLock = 0x0000014F;
        public const uint TPM2_NV_ReadPublic = 0x00000169;
        public const uint TPM2_GetCapability = 0x0000017A;
        public const uint TPM2_GetRandom = 0x0000017B;
        public const uint HR_SHIFT = 24;
        public const uint TPM_HT_NV_INDEX = 0x01;
        public const uint HR_NV_INDEX = TPM_HT_NV_INDEX << 24 /* << HR_SHIFT */;
        public const uint TPM_RH_OWNER = 0x40000001;
        public const uint TPM_RH_PLATFORM = 0x4000000C;
        public const uint TPM_RS_PW = 0x40000009;
        // TPM2 capabilities.
        public const uint TPM_CAP_FIRST = 0x00000000;
        public const uint TPM_CAP_TPM_PROPERTIES = 0x00000006;
        // TPM properties
        public const uint TPM_PT_NONE = 0x00000000;
        public const uint PT_GROUP = 0x00000100;
        public const uint PT_FIXED = PT_GROUP;
        public const uint TPM_PT_MANUFACTURER = PT_FIXED + 5;
        public const uint TPM_PT_VENDOR_STRING_1 = PT_FIXED + 6;
        public const uint TPM_PT_VENDOR_STRING_4 = PT_FIXED + 9;
        public const uint TPM_PT_FIRMWARE_VERSION_1 = PT_FIXED + 11;
        public const uint TPM_PT_FIRMWARE_VERSION_2 = PT_FIXED + 12;
        public const uint PT_VAR = PT_GROUP * 2;
        public const uint TPM_PT_PERMANENT = PT_VAR + 0;
        public const uint TPM_PT_STARTUP_CLEAR = PT_VAR + 1;
        // TPM startup types.
        public const ushort TPM_SU_CLEAR = 0x0000;
        public const ushort TPM_SU_STATE = 0x0001;
        // TPM algorithm IDs.
        public const ushort TPM_ALG_SHA1 = 0x0004;
        public const ushort TPM_ALG_SHA256 = 0x000B;
        public const ushort TPM_ALG_NULL = 0x0010;
        public const uint TPM_RH_NULL = 0x40000007;
    }

    public static class TpmReservedIndexes
    {
        public const uint TPMI_RH_NV_INDEX_TPM_START = 0x01000000;
        public const uint TPMI_RH_NV_INDEX_PLATFORM_START = 0x01400000;
        public const uint TPMI_RH_NV_INDEX_OWNER_START = 0x01800000;
        public const uint TPMI_RH_NV_INDEX_TCG_OEM_START = 0x01C00000;
        public const uint TPMI_RH_NV_INDEX_TCG_WG_START = 0x01C40000;
        public const uint TPMI_RH_NV_INDEX_RESERVED_START = 0x01C90000;
    }

    public enum TPM_HANDLE: uint
    {
        TPM_HANDLE_OWNER = 0x40000001,
        TPM_HANDLE_ENDORSEMENT = 0x4000000C,
        TPM_HANDLE_PLATFORM = 0x4000000D,
        TPM_HANDLE_LOCKOUT = 0x4000000E
    }    
}
