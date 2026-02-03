namespace Verifiable.Tpm.Structures.Spec.Constants;


/// <summary>
/// TPM_RC constants (response codes).
/// </summary>
/// <remarks>
/// <para>
/// Purpose: Response codes returned by the TPM to indicate success or specific error conditions.
/// </para>
/// <para>
/// Retrieved as the responseCode field in TPM responses.
/// </para>
/// <para>
/// Specification: TPM 2.0 Library Specification (Part 2: Structures), section "6.6 TPM_RC" (Tables
/// 16-19).
/// </para>
/// </remarks>
public enum TpmRcConstants: uint
{
    /// <summary>
    /// Successful completion.
    /// </summary>
    TPM_RC_SUCCESS = 0x000,

    /// <summary>
    /// Bad tag value.
    /// </summary>
    TPM_RC_BAD_TAG = 0x01E,

    /// <summary>
    /// Set for all format 0 response codes.
    /// </summary>
    RC_VER1 = 0x100,

    /// <summary>
    /// TPM not initialized by TPM2_Startup() or already initialized.
    /// </summary>
    TPM_RC_INITIALIZE = RC_VER1 + 0x000,

    /// <summary>
    /// Commands not being accepted because of a TPM failure Note: This can be returned by
    /// TPM2_GetTestResult() as the testResult parameter.
    /// </summary>
    TPM_RC_FAILURE = RC_VER1 + 0x001,

    /// <summary>
    /// Improper use of a sequence handle.
    /// </summary>
    TPM_RC_SEQUENCE = RC_VER1 + 0x003,

    /// <summary>
    /// Not currently used.
    /// </summary>
    TPM_RC_PRIVATE = RC_VER1 + 0x00B,

    /// <summary>
    /// Not currently used.
    /// </summary>
    TPM_RC_HMAC = RC_VER1 + 0x019,

    /// <summary>
    /// The command is disabled.
    /// </summary>
    TPM_RC_DISABLED = RC_VER1 + 0x020,

    /// <summary>
    /// Command failed because audit sequence required exclusivity.
    /// </summary>
    TPM_RC_EXCLUSIVE = RC_VER1 + 0x021,

    /// <summary>
    /// Authorization handle is not correct for command.
    /// </summary>
    TPM_RC_AUTH_TYPE = RC_VER1 + 0x024,

    /// <summary>
    /// Command requires an authorization session for handle and it is not present.
    /// </summary>
    TPM_RC_AUTH_MISSING = RC_VER1 + 0x025,

    /// <summary>
    /// Policy failure in math operation or an invalid authPolicy value.
    /// </summary>
    TPM_RC_POLICY = RC_VER1 + 0x026,

    /// <summary>
    /// PCR check fail.
    /// </summary>
    TPM_RC_PCR = RC_VER1 + 0x027,

    /// <summary>
    /// PCR have changed since checked.
    /// </summary>
    TPM_RC_PCR_CHANGED = RC_VER1 + 0x028,

    /// <summary>
    /// For all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in
    /// field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in
    /// field upgrade mode.
    /// </summary>
    TPM_RC_UPGRADE = RC_VER1 + 0x02D,

    /// <summary>
    /// Context ID counter is at maximum.
    /// </summary>
    TPM_RC_TOO_MANY_CONTEXTS = RC_VER1 + 0x02E,

    /// <summary>
    /// AuthValue or authPolicy is not available for selected entity.
    /// </summary>
    TPM_RC_AUTH_UNAVAILABLE = RC_VER1 + 0x02F,

    /// <summary>
    /// A _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.
    /// </summary>
    TPM_RC_REBOOT = RC_VER1 + 0x030,

    /// <summary>
    /// The protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of
    /// the hash must be larger than the key size of the symmetric algorithm.
    /// </summary>
    TPM_RC_UNBALANCED = RC_VER1 + 0x031,

    /// <summary>
    /// Command commandSize value is inconsistent with contents of the command buffer; either the size
    /// is not the same as the octets loaded by the hardware interface layer or the value is not large
    /// enough to hold a command header.
    /// </summary>
    TPM_RC_COMMAND_SIZE = RC_VER1 + 0x042,

    /// <summary>
    /// Command code not supported.
    /// </summary>
    TPM_RC_COMMAND_CODE = RC_VER1 + 0x043,

    /// <summary>
    /// The value of authorizationSize is out of range or the number of octets in the Authorization Area
    /// is greater than required.
    /// </summary>
    TPM_RC_AUTHSIZE = RC_VER1 + 0x044,

    /// <summary>
    /// Use of an authorization session with a context command or another command that cannot have an
    /// authorization session.
    /// </summary>
    TPM_RC_AUTH_CONTEXT = RC_VER1 + 0x045,

    /// <summary>
    /// NV offset + size is out of range.
    /// </summary>
    TPM_RC_NV_RANGE = RC_VER1 + 0x046,

    /// <summary>
    /// Requested allocation size is larger than allowed.
    /// </summary>
    TPM_RC_NV_SIZE = RC_VER1 + 0x047,

    /// <summary>
    /// NV access locked.
    /// </summary>
    TPM_RC_NV_LOCKED = RC_VER1 + 0x048,

    /// <summary>
    /// NV access authorization fails in command actions (this failure does not affect lockout.action).
    /// </summary>
    TPM_RC_NV_AUTHORIZATION = RC_VER1 + 0x049,

    /// <summary>
    /// An NV Index is used before being initialized (written) or the state saved by
    /// TPM2_Shutdown(STATE) could not be restored.
    /// </summary>
    TPM_RC_NV_UNINITIALIZED = RC_VER1 + 0x04A,

    /// <summary>
    /// Insufficient space for NV allocation.
    /// </summary>
    TPM_RC_NV_SPACE = RC_VER1 + 0x04B,

    /// <summary>
    /// NV Index or persistent object already defined.
    /// </summary>
    TPM_RC_NV_DEFINED = RC_VER1 + 0x04C,

    /// <summary>
    /// Context in TPM2_ContextLoad() is not valid.
    /// </summary>
    TPM_RC_BAD_CONTEXT = RC_VER1 + 0x050,

    /// <summary>
    /// CpHash value already set or not correct for use.
    /// </summary>
    TPM_RC_CPHASH = RC_VER1 + 0x051,

    /// <summary>
    /// Handle for parent is not a valid parent.
    /// </summary>
    TPM_RC_PARENT = RC_VER1 + 0x052,

    /// <summary>
    /// Some function needs testing.
    /// </summary>
    TPM_RC_NEEDS_TEST = RC_VER1 + 0x053,

    /// <summary>
    /// Returned when an internal function cannot process a request due to an unspecified problem. This
    /// code is usually related to invalid parameters that are not properly filtered by the input
    /// unmarshaling code.
    /// </summary>
    TPM_RC_NO_RESULT = RC_VER1 + 0x054,

    /// <summary>
    /// The sensitive area did not unmarshal correctly after decryption - this code is used in lieu of
    /// the other unmarshaling errors so that an attacker cannot determine where the unmarshaling error
    /// occurred.
    /// </summary>
    TPM_RC_SENSITIVE = RC_VER1 + 0x055,

    /// <summary>
    /// Command failed because the TPM is in the Read-Only mode of operation.
    /// </summary>
    TPM_RC_READ_ONLY = RC_VER1 + 0x056,

    /// <summary>
    /// Largest version 1 code that is not a warning.
    /// </summary>
    RC_MAX_FM0 = RC_VER1 + 0x07F,

    /// <summary>
    /// This bit is SET in all format 1 response codes The codes in this group may have a value added to
    /// them to indicate the handle, session, or parameter to which they apply.
    /// </summary>
    RC_FMT1 = 0x080,

    /// <summary>
    /// Asymmetric algorithm not supported or not correct.
    /// </summary>
    TPM_RC_ASYMMETRIC = RC_FMT1 + 0x001,

    /// <summary>
    /// Inconsistent attributes
    /// </summary>
    TPM_RC_ATTRIBUTES = RC_FMT1 + 0x002,

    /// <summary>
    /// Hash algorithm not supported or not appropriate
    /// </summary>
    TPM_RC_HASH = RC_FMT1 + 0x003,

    /// <summary>
    /// Value is out of range or is not correct for the context.
    /// </summary>
    TPM_RC_VALUE = RC_FMT1 + 0x004,

    /// <summary>
    /// Hierarchy is not enabled or is not correct for the use.
    /// </summary>
    TPM_RC_HIERARCHY = RC_FMT1 + 0x005,

    /// <summary>
    /// Key size is not supported.
    /// </summary>
    TPM_RC_KEY_SIZE = RC_FMT1 + 0x007,

    /// <summary>
    /// Mmask generation function not supported.
    /// </summary>
    TPM_RC_MGF = RC_FMT1 + 0x008,

    /// <summary>
    /// Mode of operation not supported.
    /// </summary>
    TPM_RC_MODE = RC_FMT1 + 0x009,

    /// <summary>
    /// The type of the value is not appropriate for the use.
    /// </summary>
    TPM_RC_TYPE = RC_FMT1 + 0x00A,

    /// <summary>
    /// The handle is not correct for the use.
    /// </summary>
    TPM_RC_HANDLE = RC_FMT1 + 0x00B,

    /// <summary>
    /// Unsupported key derivation function or function not appropriate for use.
    /// </summary>
    TPM_RC_KDF = RC_FMT1 + 0x00C,

    /// <summary>
    /// Value was out of allowed range.
    /// </summary>
    TPM_RC_RANGE = RC_FMT1 + 0x00D,

    /// <summary>
    /// The authorization HMAC check failed and the DA counter was incremented, or use of lockoutAuth is
    /// disabled
    /// </summary>
    TPM_RC_AUTH_FAIL = RC_FMT1 + 0x00E,

    /// <summary>
    /// Invalid nonce size or nonce value mismatch.
    /// </summary>
    TPM_RC_NONCE = RC_FMT1 + 0x00F,

    /// <summary>
    /// Authorization requires assertion of PP.
    /// </summary>
    TPM_RC_PP = RC_FMT1 + 0x010,

    /// <summary>
    /// Unsupported or incompatible scheme.
    /// </summary>
    TPM_RC_SCHEME = RC_FMT1 + 0x012,

    /// <summary>
    /// Structure is the wrong size.
    /// </summary>
    TPM_RC_SIZE = RC_FMT1 + 0x015,

    /// <summary>
    /// Unsupported symmetric algorithm or key size, or not appropriate for instance
    /// </summary>
    TPM_RC_SYMMETRIC = RC_FMT1 + 0x016,

    /// <summary>
    /// Incorrect structure tag.
    /// </summary>
    TPM_RC_TAG = RC_FMT1 + 0x017,

    /// <summary>
    /// Union selector is incorrect.
    /// </summary>
    TPM_RC_SELECTOR = RC_FMT1 + 0x018,

    /// <summary>
    /// The TPM was unable to unmarshal a value because there were not enough octets in the input buffer
    /// </summary>
    TPM_RC_INSUFFICIENT = RC_FMT1 + 0x01A,

    /// <summary>
    /// The signature is not valid.
    /// </summary>
    TPM_RC_SIGNATURE = RC_FMT1 + 0x01B,

    /// <summary>
    /// Key fields are not compatible with the selected use.
    /// </summary>
    TPM_RC_KEY = RC_FMT1 + 0x01C,

    /// <summary>
    /// A policy check failed.
    /// </summary>
    TPM_RC_POLICY_FAIL = RC_FMT1 + 0x01D,

    /// <summary>
    /// Integrity check failed.
    /// </summary>
    TPM_RC_INTEGRITY = RC_FMT1 + 0x01F,

    /// <summary>
    /// Invalid ticket.
    /// </summary>
    TPM_RC_TICKET = RC_FMT1 + 0x020,

    /// <summary>
    /// Reserved bits not set to zero as required.
    /// </summary>
    TPM_RC_RESERVED_BITS = RC_FMT1 + 0x021,

    /// <summary>
    /// Authorization failure without DA implications.
    /// </summary>
    TPM_RC_BAD_AUTH = RC_FMT1 + 0x022,

    /// <summary>
    /// The policy has expired.
    /// </summary>
    TPM_RC_EXPIRED = RC_FMT1 + 0x023,

    /// <summary>
    /// The commandCode in the policy is not the commandCode of the command or the command code in a
    /// policy command references a command that is not implemented.
    /// </summary>
    TPM_RC_POLICY_CC = RC_FMT1 + 0x024,

    /// <summary>
    /// Public and sensitive portions of an object are not cryptographically bound.
    /// </summary>
    TPM_RC_BINDING = RC_FMT1 + 0x025,

    /// <summary>
    /// Curve not supported.
    /// </summary>
    TPM_RC_CURVE = RC_FMT1 + 0x026,

    /// <summary>
    /// Point is not on the required curve.
    /// </summary>
    TPM_RC_ECC_POINT = RC_FMT1 + 0x027,

    /// <summary>
    /// The hierarchy is firmware-limited but the Firmware Secret is unavailable.
    /// </summary>
    TPM_RC_FW_LIMITED = RC_FMT1 + 0x028,

    /// <summary>
    /// The hierarchy is SVN-limited but the Firmware SVN Secret associated with the given SVN is
    /// unavailable.
    /// </summary>
    TPM_RC_SVN_LIMITED = RC_FMT1 + 0x029,

    /// <summary>
    /// Command requires secure channel protection.
    /// </summary>
    TPM_RC_CHANNEL = RC_FMT1 + 0x030,

    /// <summary>
    /// Secure channel was not established with required requester or TPM key.
    /// </summary>
    TPM_RC_CHANNEL_KEY = RC_FMT1 + 0x031,

    /// <summary>
    /// Set for warning response codes.
    /// </summary>
    RC_WARN = 0x900,

    /// <summary>
    /// Gap for context ID is too large.
    /// </summary>
    TPM_RC_CONTEXT_GAP = RC_WARN + 0x001,

    /// <summary>
    /// Out of memory for object contexts.
    /// </summary>
    TPM_RC_OBJECT_MEMORY = RC_WARN + 0x002,

    /// <summary>
    /// Out of memory for session contexts.
    /// </summary>
    TPM_RC_SESSION_MEMORY = RC_WARN + 0x003,

    /// <summary>
    /// Out of shared object/session memory or need space for internal operations.
    /// </summary>
    TPM_RC_MEMORY = RC_WARN + 0x004,

    /// <summary>
    /// Out of session handles - a session must be flushed before a new session may be created.
    /// </summary>
    TPM_RC_SESSION_HANDLES = RC_WARN + 0x005,

    /// <summary>
    /// Out of object handles - the handle space for objects is depleted and a reboot is required Note:
    /// This cannot occur when using the Reference Code. . Note: There is no reason why an
    /// implementation would implement a design that would deplete handle space. Platform specifications
    /// are encouraged to forbid it.
    /// </summary>
    TPM_RC_OBJECT_HANDLES = RC_WARN + 0x006,

    /// <summary>
    /// bad locality
    /// </summary>
    TPM_RC_LOCALITY = RC_WARN + 0x007,

    /// <summary>
    /// The TPM has suspended operation on the command; forward progress was made and the command may be
    /// retried See TPM 2.0 Part 1, “Multi-tasking.” Note: This cannot occur when using the Reference
    /// Code.
    /// </summary>
    TPM_RC_YIELDED = RC_WARN + 0x008,

    /// <summary>
    /// The command was canceled.
    /// </summary>
    TPM_RC_CANCELED = RC_WARN + 0x009,

    /// <summary>
    /// TPM is performing self-tests.
    /// </summary>
    TPM_RC_TESTING = RC_WARN + 0x00A,

    /// <summary>
    /// The 1st handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H0 = RC_WARN + 0x010,

    /// <summary>
    /// The 2nd handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H1 = RC_WARN + 0x011,

    /// <summary>
    /// The 3rd handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H2 = RC_WARN + 0x012,

    /// <summary>
    /// The 4th handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H3 = RC_WARN + 0x013,

    /// <summary>
    /// The 5th handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H4 = RC_WARN + 0x014,

    /// <summary>
    /// The 6th handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H5 = RC_WARN + 0x015,

    /// <summary>
    /// The 7th handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H6 = RC_WARN + 0x016,

    /// <summary>
    /// The 1st authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S0 = RC_WARN + 0x018,

    /// <summary>
    /// The 2nd authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S1 = RC_WARN + 0x019,

    /// <summary>
    /// The 3rd authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S2 = RC_WARN + 0x01A,

    /// <summary>
    /// The 4th authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S3 = RC_WARN + 0x01B,

    /// <summary>
    /// The 5th session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S4 = RC_WARN + 0x01C,

    /// <summary>
    /// The 6th session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S5 = RC_WARN + 0x01D,

    /// <summary>
    /// The 7th authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S6 = RC_WARN + 0x01E,

    /// <summary>
    /// The TPM is rate-limiting accesses to prevent wearout of NV.
    /// </summary>
    TPM_RC_NV_RATE = RC_WARN + 0x020,

    /// <summary>
    /// Authorizations for objects subject to DA protection are not allowed at this time because the TPM
    /// is in DA lockout mode
    /// </summary>
    TPM_RC_LOCKOUT = RC_WARN + 0x021,

    /// <summary>
    /// The TPM was not able to start the command.
    /// </summary>
    TPM_RC_RETRY = RC_WARN + 0x022,

    /// <summary>
    /// The command may require writing of NV and NV is not current accessible.
    /// </summary>
    TPM_RC_NV_UNAVAILABLE = RC_WARN + 0x023,

    /// <summary>
    /// This value is reserved and shall not be returned by the TPM.
    /// </summary>
    TPM_RC_NOT_USED = RC_WARN + 0x7F,

    /// <summary>
    /// Add to a handle-related error.
    /// </summary>
    TPM_RC_H = 0x000,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_P = 0x040,

    /// <summary>
    /// Add to a session-related error.
    /// </summary>
    TPM_RC_S = 0x800,

    /// <summary>
    /// Add to a parameter-, handle-, or session-related error.
    /// </summary>
    TPM_RC_1 = 0x100,

    /// <summary>
    /// Add to a parameter-, handle-, or session-related error.
    /// </summary>
    TPM_RC_2 = 0x200,

    /// <summary>
    /// Add to a parameter-, handle-, or session-related error.
    /// </summary>
    TPM_RC_3 = 0x300,

    /// <summary>
    /// Add to a parameter-, handle-, or session-related error.
    /// </summary>
    TPM_RC_4 = 0x400,

    /// <summary>
    /// Add to a parameter-, handle-, or session-related error.
    /// </summary>
    TPM_RC_5 = 0x500,

    /// <summary>
    /// Add to a parameter-, handle-, or session-related error.
    /// </summary>
    TPM_RC_6 = 0x600,

    /// <summary>
    /// Add to a parameter-, handle-, or session-related error.
    /// </summary>
    TPM_RC_7 = 0x700,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_8 = 0x800,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_9 = 0x900,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_A = 0xA00,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_B = 0xB00,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_C = 0xC00,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_D = 0xD00,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_E = 0xE00,

    /// <summary>
    /// Add to a parameter-related error.
    /// </summary>
    TPM_RC_F = 0xF00,

    /// <summary>
    /// Number mask.
    /// </summary>
    TPM_RC_N_MASK = 0xF00
}