﻿namespace Verifiable.Tpm
{
    public static class Tpm2PtConstants
    {
        public const uint TPM2_PT_NONE = 0x00000000;
        public const uint TPM2_PT_GROUP = 0x00000100;
        public const uint TPM2_PT_FIXED = TPM2_PT_GROUP * 1;
        public const uint TPM2_PT_FAMILY_INDICATOR = TPM2_PT_FIXED + 0;
        public const uint TPM2_PT_LEVEL = TPM2_PT_FIXED + 1;
        public const uint TPM2_PT_REVISION = TPM2_PT_FIXED + 2;
        public const uint TPM2_PT_DAY_OF_YEAR = TPM2_PT_FIXED + 3;
        public const uint TPM2_PT_YEAR = TPM2_PT_FIXED + 4;
        public const uint TPM2_PT_MANUFACTURER = TPM2_PT_FIXED + 5;
        public const uint TPM2_PT_VENDOR_STRING_1 = TPM2_PT_FIXED + 6;
        public const uint TPM2_PT_VENDOR_STRING_2 = TPM2_PT_FIXED + 7;
        public const uint TPM2_PT_VENDOR_STRING_3 = TPM2_PT_FIXED + 8;
        public const uint TPM2_PT_VENDOR_STRING_4 = TPM2_PT_FIXED + 9;
        public const uint TPM2_PT_VENDOR_TPM_TYPE = TPM2_PT_FIXED + 10;
        public const uint TPM2_PT_FIRMWARE_VERSION_1 = TPM2_PT_FIXED + 11;
        public const uint TPM2_PT_FIRMWARE_VERSION_2 = TPM2_PT_FIXED + 12;
        public const uint TPM2_PT_INPUT_BUFFER = TPM2_PT_FIXED + 13;
        public const uint TPM2_PT_HR_TRANSIENT_MIN = TPM2_PT_FIXED + 14;
        public const uint TPM2_PT_HR_PERSISTENT_MIN = TPM2_PT_FIXED + 15;
        public const uint TPM2_PT_HR_LOADED_MIN = TPM2_PT_FIXED + 16;
        public const uint TPM2_PT_ACTIVE_SESSIONS_MAX = TPM2_PT_FIXED + 17;
        public const uint TPM2_PT_PCR_COUNT = TPM2_PT_FIXED + 18;
        public const uint TPM2_PT_PCR_SELECT_MIN = TPM2_PT_FIXED + 19;
        public const uint TPM2_PT_CONTEXT_GAP_MAX = TPM2_PT_FIXED + 20;
        public const uint TPM2_PT_NV_COUNTERS_MAX = TPM2_PT_FIXED + 22;
        public const uint TPM2_PT_NV_INDEX_MAX = TPM2_PT_FIXED + 23;
        public const uint TPM2_PT_MEMORY = TPM2_PT_FIXED + 24;
        public const uint TPM2_PT_CLOCK_UPDATE = TPM2_PT_FIXED + 25;
        public const uint TPM2_PT_CONTEXT_HASH = TPM2_PT_FIXED + 26;
        public const uint TPM2_PT_CONTEXT_SYM = TPM2_PT_FIXED + 27;
        public const uint TPM2_PT_CONTEXT_SYM_SIZE = TPM2_PT_FIXED + 28;
        public const uint TPM2_PT_ORDERLY_COUNT = TPM2_PT_FIXED + 29;
        public const uint TPM2_PT_MAX_COMMAND_SIZE = TPM2_PT_FIXED + 30;
        public const uint TPM2_PT_MAX_RESPONSE_SIZE = TPM2_PT_FIXED + 31;
        public const uint TPM2_PT_MAX_DIGEST = TPM2_PT_FIXED + 32;
        public const uint TPM2_PT_MAX_OBJECT_CONTEXT = TPM2_PT_FIXED + 33;
        public const uint TPM2_PT_MAX_SESSION_CONTEXT = TPM2_PT_FIXED + 34;
        public const uint TPM2_PT_PS_FAMILY_INDICATOR = TPM2_PT_FIXED + 35;
        public const uint TPM2_PT_PS_LEVEL = TPM2_PT_FIXED + 36;
        public const uint TPM2_PT_PS_REVISION = TPM2_PT_FIXED + 37;
        public const uint TPM2_PT_PS_DAY_OF_YEAR = TPM2_PT_FIXED + 38;
        public const uint TPM2_PT_PS_YEAR = TPM2_PT_FIXED + 39;
        public const uint TPM2_PT_SPLIT_MAX = TPM2_PT_FIXED + 40;
        public const uint TPM2_PT_TOTAL_COMMANDS = TPM2_PT_FIXED + 41;
        public const uint TPM2_PT_LIBRARY_COMMANDS = TPM2_PT_FIXED + 42;
        public const uint TPM2_PT_VENDOR_COMMANDS = TPM2_PT_FIXED + 43;
        public const uint TPM2_PT_NV_BUFFER_MAX = TPM2_PT_FIXED + 44;
        public const uint TPM2_PT_MODES = TPM2_PT_FIXED + 45;
        public const uint TPM2_PT_MAX_CAP_BUFFER = TPM2_PT_FIXED + 46;
        public const uint TPM2_PT_VAR = TPM2_PT_GROUP * 2;
        public const uint TPM2_PT_PERMANENT = TPM2_PT_VAR + 0;
        public const uint TPM2_PT_STARTUP_CLEAR = TPM2_PT_VAR + 1;
        public const uint TPM2_PT_HR_NV_INDEX = TPM2_PT_VAR + 2;
        public const uint TPM2_PT_HR_LOADED = TPM2_PT_VAR + 3;
        public const uint TPM2_PT_HR_LOADED_AVAIL = TPM2_PT_VAR + 4;
        public const uint TPM2_PT_HR_ACTIVE = TPM2_PT_VAR + 5;
        public const uint TPM2_PT_HR_ACTIVE_AVAIL = TPM2_PT_VAR + 6;
        public const uint TPM2_PT_HR_TRANSIENT_AVAIL = TPM2_PT_VAR + 7;
        public const uint TPM2_PT_HR_PERSISTENT = TPM2_PT_VAR + 8;
        public const uint TPM2_PT_HR_PERSISTENT_AVAIL = TPM2_PT_VAR + 9;
        public const uint TPM2_PT_NV_COUNTERS = TPM2_PT_VAR + 10;
        public const uint TPM2_PT_NV_COUNTERS_AVAIL = TPM2_PT_VAR + 11;
        public const uint TPM2_PT_ALGORITHM_SET = TPM2_PT_VAR + 12;
        public const uint TPM2_PT_LOADED_CURVES = TPM2_PT_VAR + 13;
        public const uint TPM2_PT_LOCKOUT_COUNTER = TPM2_PT_VAR + 14;
        public const uint TPM2_PT_MAX_AUTH_FAIL = TPM2_PT_VAR + 15;
        public const uint TPM2_PT_LOCKOUT_INTERVAL = TPM2_PT_VAR + 16;
        public const uint TPM2_PT_LOCKOUT_RECOVERY = TPM2_PT_VAR + 17;
        public const uint TPM2_PT_NV_WRITE_RECOVERY = TPM2_PT_VAR + 18;
        public const uint TPM2_PT_AUDIT_COUNTER_0 = TPM2_PT_VAR + 19;
        public const uint TPM2_PT_AUDIT_COUNTER_1 = TPM2_PT_VAR + 20;
    }
}