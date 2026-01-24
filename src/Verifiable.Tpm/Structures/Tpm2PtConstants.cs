namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM 2.0 property constants (TPM_PT) for use with TPM2_GetCapability.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 6.13 - TPM_PT.
/// </para>
/// </remarks>
public enum Tpm2PtConstants: uint
{
    /// <summary>
    /// TPM_PT_NONE: Indicates no property type.
    /// </summary>
    TPM_PT_NONE = 0x00000000,

    /// <summary>
    /// PT_GROUP: Property group multiplier.
    /// </summary>
    PT_GROUP = 0x00000100,

    /// <summary>
    /// PT_FIXED: Base value for fixed TPM properties.
    /// </summary>
    PT_FIXED = 0x00000100,

    /// <summary>
    /// TPM_PT_FAMILY_INDICATOR: TPM Family value (TPM_SPEC_FAMILY).
    /// </summary>
    TPM2_PT_FAMILY_INDICATOR = 0x00000100,

    /// <summary>
    /// TPM_PT_LEVEL: Specification level (TPM_SPEC_LEVEL).
    /// </summary>
    TPM2_PT_LEVEL = 0x00000101,

    /// <summary>
    /// TPM_PT_REVISION: Specification revision times 100.
    /// </summary>
    TPM2_PT_REVISION = 0x00000102,

    /// <summary>
    /// TPM_PT_DAY_OF_YEAR: Specification day of year.
    /// </summary>
    TPM2_PT_DAY_OF_YEAR = 0x00000103,

    /// <summary>
    /// TPM_PT_YEAR: Specification year.
    /// </summary>
    TPM2_PT_YEAR = 0x00000104,

    /// <summary>
    /// TPM_PT_MANUFACTURER: Vendor ID unique to each TPM manufacturer.
    /// </summary>
    TPM2_PT_MANUFACTURER = 0x00000105,

    /// <summary>
    /// TPM_PT_VENDOR_STRING_1: First four characters of vendor ID string.
    /// </summary>
    TPM2_PT_VENDOR_STRING_1 = 0x00000106,

    /// <summary>
    /// TPM_PT_VENDOR_STRING_2: Second four characters of vendor ID string.
    /// </summary>
    TPM2_PT_VENDOR_STRING_2 = 0x00000107,

    /// <summary>
    /// TPM_PT_VENDOR_STRING_3: Third four characters of vendor ID string.
    /// </summary>
    TPM2_PT_VENDOR_STRING_3 = 0x00000108,

    /// <summary>
    /// TPM_PT_VENDOR_STRING_4: Fourth four characters of vendor ID string.
    /// </summary>
    TPM2_PT_VENDOR_STRING_4 = 0x00000109,

    /// <summary>
    /// TPM_PT_VENDOR_TPM_TYPE: Vendor-defined TPM model value.
    /// </summary>
    TPM2_PT_VENDOR_TPM_TYPE = 0x0000010A,

    /// <summary>
    /// TPM_PT_FIRMWARE_VERSION_1: Most-significant 32 bits of firmware version.
    /// </summary>
    TPM2_PT_FIRMWARE_VERSION_1 = 0x0000010B,

    /// <summary>
    /// TPM_PT_FIRMWARE_VERSION_2: Least-significant 32 bits of firmware version.
    /// </summary>
    TPM2_PT_FIRMWARE_VERSION_2 = 0x0000010C,

    /// <summary>
    /// TPM_PT_INPUT_BUFFER: Maximum size of a parameter (typically TPM2B_MAX_BUFFER).
    /// </summary>
    TPM2_PT_INPUT_BUFFER = 0x0000010D,

    /// <summary>
    /// TPM_PT_HR_TRANSIENT_MIN: Minimum transient objects in TPM RAM.
    /// </summary>
    TPM2_PT_HR_TRANSIENT_MIN = 0x0000010E,

    /// <summary>
    /// TPM_PT_HR_PERSISTENT_MIN: Minimum persistent objects in TPM NV.
    /// </summary>
    TPM2_PT_HR_PERSISTENT_MIN = 0x0000010F,

    /// <summary>
    /// TPM_PT_HR_LOADED_MIN: Minimum authorization sessions in TPM RAM.
    /// </summary>
    TPM2_PT_HR_LOADED_MIN = 0x00000110,

    /// <summary>
    /// TPM_PT_ACTIVE_SESSIONS_MAX: Maximum simultaneous active sessions.
    /// </summary>
    TPM2_PT_ACTIVE_SESSIONS_MAX = 0x00000111,

    /// <summary>
    /// TPM_PT_PCR_COUNT: Number of PCR implemented.
    /// </summary>
    TPM2_PT_PCR_COUNT = 0x00000112,

    /// <summary>
    /// TPM_PT_PCR_SELECT_MIN: Minimum octets in TPMS_PCR_SELECT.sizeofSelect.
    /// </summary>
    TPM2_PT_PCR_SELECT_MIN = 0x00000113,

    /// <summary>
    /// TPM_PT_CONTEXT_GAP_MAX: Maximum contextID difference for saved sessions.
    /// </summary>
    TPM2_PT_CONTEXT_GAP_MAX = 0x00000114,

    /// <summary>
    /// TPM_PT_NV_COUNTERS_MAX: Maximum NV Indexes with TPMA_NV_COUNTER SET.
    /// </summary>
    TPM2_PT_NV_COUNTERS_MAX = 0x00000116,

    /// <summary>
    /// TPM_PT_NV_INDEX_MAX: Maximum size of an NV Index data area.
    /// </summary>
    TPM2_PT_NV_INDEX_MAX = 0x00000117,

    /// <summary>
    /// TPM_PT_MEMORY: TPMA_MEMORY indicating memory management method.
    /// </summary>
    TPM2_PT_MEMORY = 0x00000118,

    /// <summary>
    /// TPM_PT_CLOCK_UPDATE: Milliseconds between NV clock updates.
    /// </summary>
    TPM2_PT_CLOCK_UPDATE = 0x00000119,

    /// <summary>
    /// TPM_PT_CONTEXT_HASH: Algorithm for integrity HMAC on saved contexts.
    /// </summary>
    TPM2_PT_CONTEXT_HASH = 0x0000011A,

    /// <summary>
    /// TPM_PT_CONTEXT_SYM: Symmetric algorithm for object encryption.
    /// </summary>
    TPM2_PT_CONTEXT_SYM = 0x0000011B,

    /// <summary>
    /// TPM_PT_CONTEXT_SYM_SIZE: Key size in bits for context encryption.
    /// </summary>
    TPM2_PT_CONTEXT_SYM_SIZE = 0x0000011C,

    /// <summary>
    /// TPM_PT_ORDERLY_COUNT: Maximum contextID difference for sessions.
    /// </summary>
    TPM2_PT_ORDERLY_COUNT = 0x0000011D,

    /// <summary>
    /// TPM_PT_MAX_COMMAND_SIZE: Maximum command size including header.
    /// </summary>
    TPM2_PT_MAX_COMMAND_SIZE = 0x0000011E,

    /// <summary>
    /// TPM_PT_MAX_RESPONSE_SIZE: Maximum response size including header.
    /// </summary>
    TPM2_PT_MAX_RESPONSE_SIZE = 0x0000011F,

    /// <summary>
    /// TPM_PT_MAX_DIGEST: Maximum digest size the TPM can produce.
    /// </summary>
    TPM2_PT_MAX_DIGEST = 0x00000120,

    /// <summary>
    /// TPM_PT_MAX_OBJECT_CONTEXT: Maximum object context size.
    /// </summary>
    TPM2_PT_MAX_OBJECT_CONTEXT = 0x00000121,

    /// <summary>
    /// TPM_PT_MAX_SESSION_CONTEXT: Maximum session context size.
    /// </summary>
    TPM2_PT_MAX_SESSION_CONTEXT = 0x00000122,

    /// <summary>
    /// TPM_PT_PS_FAMILY_INDICATOR: Platform-specific family (TPM_PS value).
    /// </summary>
    TPM2_PT_PS_FAMILY_INDICATOR = 0x00000123,

    /// <summary>
    /// TPM_PT_PS_LEVEL: Platform-specific specification level.
    /// </summary>
    TPM2_PT_PS_LEVEL = 0x00000124,

    /// <summary>
    /// TPM_PT_PS_REVISION: Platform-specific specification revision times 100.
    /// </summary>
    TPM2_PT_PS_REVISION = 0x00000125,

    /// <summary>
    /// TPM_PT_PS_DAY_OF_YEAR: Platform-specific specification day of year.
    /// </summary>
    TPM2_PT_PS_DAY_OF_YEAR = 0x00000126,

    /// <summary>
    /// TPM_PT_PS_YEAR: Platform-specific specification year.
    /// </summary>
    TPM2_PT_PS_YEAR = 0x00000127,

    /// <summary>
    /// TPM_PT_SPLIT_MAX: Number of split signing operations supported.
    /// </summary>
    TPM2_PT_SPLIT_MAX = 0x00000128,

    /// <summary>
    /// TPM_PT_TOTAL_COMMANDS: Total commands implemented.
    /// </summary>
    TPM2_PT_TOTAL_COMMANDS = 0x00000129,

    /// <summary>
    /// TPM_PT_LIBRARY_COMMANDS: TPM library commands implemented.
    /// </summary>
    TPM2_PT_LIBRARY_COMMANDS = 0x0000012A,

    /// <summary>
    /// TPM_PT_VENDOR_COMMANDS: Vendor commands implemented.
    /// </summary>
    TPM2_PT_VENDOR_COMMANDS = 0x0000012B,

    /// <summary>
    /// TPM_PT_NV_BUFFER_MAX: Maximum data size in single NV write.
    /// </summary>
    TPM2_PT_NV_BUFFER_MAX = 0x0000012C,

    /// <summary>
    /// TPM_PT_MODES: TPMA_MODES value indicating TPM mode of operation.
    /// </summary>
    TPM2_PT_MODES = 0x0000012D,

    /// <summary>
    /// TPM_PT_MAX_CAP_BUFFER: Maximum TPMS_CAPABILITY_DATA size.
    /// </summary>
    TPM2_PT_MAX_CAP_BUFFER = 0x0000012E,

    /// <summary>
    /// PT_VAR: Base value for variable TPM properties.
    /// </summary>
    PT_VAR = 0x00000200,

    /// <summary>
    /// TPM_PT_PERMANENT: TPMA_PERMANENT flags.
    /// </summary>
    TPM2_PT_PERMANENT = 0x00000200,

    /// <summary>
    /// TPM_PT_STARTUP_CLEAR: TPMA_STARTUP_CLEAR flags.
    /// </summary>
    TPM2_PT_STARTUP_CLEAR = 0x00000201,

    /// <summary>
    /// TPM_PT_HR_NV_INDEX: Number of NV Indexes currently defined.
    /// </summary>
    TPM2_PT_HR_NV_INDEX = 0x00000202,

    /// <summary>
    /// TPM_PT_HR_LOADED: Authorization sessions currently loaded.
    /// </summary>
    TPM2_PT_HR_LOADED = 0x00000203,

    /// <summary>
    /// TPM_PT_HR_LOADED_AVAIL: Additional sessions that could be loaded.
    /// </summary>
    TPM2_PT_HR_LOADED_AVAIL = 0x00000204,

    /// <summary>
    /// TPM_PT_HR_ACTIVE: Active authorization sessions tracked.
    /// </summary>
    TPM2_PT_HR_ACTIVE = 0x00000205,

    /// <summary>
    /// TPM_PT_HR_ACTIVE_AVAIL: Additional sessions that could be created.
    /// </summary>
    TPM2_PT_HR_ACTIVE_AVAIL = 0x00000206,

    /// <summary>
    /// TPM_PT_HR_TRANSIENT_AVAIL: Additional transient objects that could be loaded.
    /// </summary>
    TPM2_PT_HR_TRANSIENT_AVAIL = 0x00000207,

    /// <summary>
    /// TPM_PT_HR_PERSISTENT: Persistent objects currently loaded.
    /// </summary>
    TPM2_PT_HR_PERSISTENT = 0x00000208,

    /// <summary>
    /// TPM_PT_HR_PERSISTENT_AVAIL: Additional persistent objects that could be loaded.
    /// </summary>
    TPM2_PT_HR_PERSISTENT_AVAIL = 0x00000209,

    /// <summary>
    /// TPM_PT_NV_COUNTERS: NV Indexes with TPMA_NV_COUNTER SET.
    /// </summary>
    TPM2_PT_NV_COUNTERS = 0x0000020A,

    /// <summary>
    /// TPM_PT_NV_COUNTERS_AVAIL: Additional NV counter Indexes that can be defined.
    /// </summary>
    TPM2_PT_NV_COUNTERS_AVAIL = 0x0000020B,

    /// <summary>
    /// TPM_PT_ALGORITHM_SET: Code limiting allowed algorithms.
    /// </summary>
    TPM2_PT_ALGORITHM_SET = 0x0000020C,

    /// <summary>
    /// TPM_PT_LOADED_CURVES: Number of loaded ECC curves.
    /// </summary>
    TPM2_PT_LOADED_CURVES = 0x0000020D,

    /// <summary>
    /// TPM_PT_LOCKOUT_COUNTER: Current lockout counter value (failedTries).
    /// </summary>
    TPM2_PT_LOCKOUT_COUNTER = 0x0000020E,

    /// <summary>
    /// TPM_PT_MAX_AUTH_FAIL: Authorization failures before lockout.
    /// </summary>
    TPM2_PT_MAX_AUTH_FAIL = 0x0000020F,

    /// <summary>
    /// TPM_PT_LOCKOUT_INTERVAL: Seconds before lockout counter decrements.
    /// </summary>
    TPM2_PT_LOCKOUT_INTERVAL = 0x00000210,

    /// <summary>
    /// TPM_PT_LOCKOUT_RECOVERY: Seconds after lockout before TPM2_Clear allowed.
    /// </summary>
    TPM2_PT_LOCKOUT_RECOVERY = 0x00000211,

    /// <summary>
    /// TPM_PT_NV_WRITE_RECOVERY: Milliseconds before NV counter may be written.
    /// </summary>
    TPM2_PT_NV_WRITE_RECOVERY = 0x00000212,

    /// <summary>
    /// TPM_PT_AUDIT_COUNTER_0: High-order 32 bits of audit counter.
    /// </summary>
    TPM2_PT_AUDIT_COUNTER_0 = 0x00000213,

    /// <summary>
    /// TPM_PT_AUDIT_COUNTER_1: Low-order 32 bits of audit counter.
    /// </summary>
    TPM2_PT_AUDIT_COUNTER_1 = 0x00000214
}