using System;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM 2.0 response codes (TPM_RC).
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 6.6 - TPM_RC.
/// </para>
/// </remarks>
public enum TpmRc: uint
{
    /// <summary>
    /// TPM_RC_SUCCESS: Command completed successfully.
    /// </summary>
    Success = 0x000,

    /// <summary>
    /// TPM_RC_BAD_TAG: Undefined tag in command header.
    /// </summary>
    TPM_RC_BAD_TAG = 0x01E,

    /// <summary>
    /// RC_VER1: Set for all format 1 response codes.
    /// </summary>
    RC_VER1 = 0x100,

    /// <summary>
    /// TPM_RC_INITIALIZE: TPM not initialized by TPM2_Startup or already initialized.
    /// </summary>
    TPM_RC_INITIALIZE = 0x100,

    /// <summary>
    /// TPM_RC_FAILURE: Commands not being accepted because of a TPM failure.
    /// </summary>
    Failure = 0x101,

    /// <summary>
    /// TPM_RC_SEQUENCE: Improper use of a sequence handle.
    /// </summary>
    TPM_RC_SEQUENCE = 0x103,

    /// <summary>
    /// TPM_RC_PRIVATE: Not currently used.
    /// </summary>
    TPM_RC_PRIVATE = 0x10B,

    /// <summary>
    /// TPM_RC_HMAC: Not currently used.
    /// </summary>
    TPM_RC_HMAC = 0x119,

    /// <summary>
    /// TPM_RC_DISABLED: The command is disabled.
    /// </summary>
    TPM_RC_DISABLED = 0x120,

    /// <summary>
    /// TPM_RC_EXCLUSIVE: Command failed because audit sequence required exclusivity.
    /// </summary>
    TPM_RC_EXCLUSIVE = 0x121,

    /// <summary>
    /// TPM_RC_AUTH_TYPE: Authorization handle is not correct for command.
    /// </summary>
    TPM_RC_AUTH_TYPE = 0x124,

    /// <summary>
    /// TPM_RC_AUTH_MISSING: Command requires an authorization session for handle and it is not present.
    /// </summary>
    TPM_RC_AUTH_MISSING = 0x125,

    /// <summary>
    /// TPM_RC_POLICY: Policy failure in math operation or invalid authPolicy value.
    /// </summary>
    TPM_RC_POLICY = 0x126,

    /// <summary>
    /// TPM_RC_PCR: PCR check failed.
    /// </summary>
    TPM_RC_PCR = 0x127,

    /// <summary>
    /// TPM_RC_PCR_CHANGED: PCR have changed since checked.
    /// </summary>
    TPM_RC_PCR_CHANGED = 0x128,

    /// <summary>
    /// TPM_RC_UPGRADE: For all commands other than TPM2_FieldUpgradeData, this code indicates that the TPM is in field upgrade mode.
    /// </summary>
    TPM_RC_UPGRADE = 0x12D,

    /// <summary>
    /// TPM_RC_TOO_MANY_CONTEXTS: Context ID counter is at maximum.
    /// </summary>
    TPM_RC_TOO_MANY_CONTEXTS = 0x12E,

    /// <summary>
    /// TPM_RC_AUTH_UNAVAILABLE: AuthValue or authPolicy is not available for selected entity.
    /// </summary>
    TPM_RC_AUTH_UNAVAILABLE = 0x12F,

    /// <summary>
    /// TPM_RC_REBOOT: A _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.
    /// </summary>
    TPM_RC_REBOOT = 0x130,

    /// <summary>
    /// TPM_RC_UNBALANCED: The protection algorithms (hash and symmetric) are not reasonably balanced.
    /// </summary>
    TPM_RC_UNBALANCED = 0x131,

    /// <summary>
    /// TPM_RC_COMMAND_SIZE: Command commandSize value is inconsistent with contents of the command buffer.
    /// </summary>
    TPM_RC_COMMAND_SIZE = 0x142,

    /// <summary>
    /// TPM_RC_COMMAND_CODE: Command code not supported.
    /// </summary>
    TPM_RC_COMMAND_CODE = 0x143,

    /// <summary>
    /// TPM_RC_AUTHSIZE: The value of authorizationSize is out of range or the number of octets in the authorization area is greater than required.
    /// </summary>
    TPM_RC_AUTHSIZE = 0x144,

    /// <summary>
    /// TPM_RC_AUTH_CONTEXT: Use of an authorization session with a context command or another command that cannot have an authorization session.
    /// </summary>
    TPM_RC_AUTH_CONTEXT = 0x145,

    /// <summary>
    /// TPM_RC_NV_RANGE: NV offset+size is out of range.
    /// </summary>
    TPM_RC_NV_RANGE = 0x146,

    /// <summary>
    /// TPM_RC_NV_SIZE: Requested allocation size is larger than allowed.
    /// </summary>
    TPM_RC_NV_SIZE = 0x147,

    /// <summary>
    /// TPM_RC_NV_LOCKED: NV access locked.
    /// </summary>
    TPM_RC_NV_LOCKED = 0x148,

    /// <summary>
    /// TPM_RC_NV_AUTHORIZATION: NV access authorization fails in command actions.
    /// </summary>
    TPM_RC_NV_AUTHORIZATION = 0x149,

    /// <summary>
    /// TPM_RC_NV_UNINITIALIZED: An NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored.
    /// </summary>
    TPM_RC_NV_UNINITIALIZED = 0x14A,

    /// <summary>
    /// TPM_RC_NV_SPACE: Insufficient space for NV allocation.
    /// </summary>
    TPM_RC_NV_SPACE = 0x14B,

    /// <summary>
    /// TPM_RC_NV_DEFINED: NV Index or persistent object already defined.
    /// </summary>
    TPM_RC_NV_DEFINED = 0x14C,

    /// <summary>
    /// TPM_RC_BAD_CONTEXT: Context in TPM2_ContextLoad is not valid.
    /// </summary>
    TPM_RC_BAD_CONTEXT = 0x150,

    /// <summary>
    /// TPM_RC_CPHASH: cpHash value already set or not correct for use.
    /// </summary>
    TPM_RC_CPHASH = 0x151,

    /// <summary>
    /// TPM_RC_PARENT: Handle for parent is not a valid parent.
    /// </summary>
    TPM_RC_PARENT = 0x152,

    /// <summary>
    /// TPM_RC_NEEDS_TEST: Some function needs testing.
    /// </summary>
    TPM_RC_NEEDS_TEST = 0x153,

    /// <summary>
    /// TPM_RC_NO_RESULT: Returned when an internal function cannot process a request due to an unspecified problem.
    /// </summary>
    TPM_RC_NO_RESULT = 0x154,

    /// <summary>
    /// TPM_RC_SENSITIVE: The sensitive area did not unmarshal correctly after decryption.
    /// </summary>
    TPM_RC_SENSITIVE = 0x155,

    /// <summary>
    /// RC_MAX_FM0: Largest format 0 code that is not a warning.
    /// </summary>
    RC_MAX_FM0 = 0x07F,

    /// <summary>
    /// RC_FMT1: Format 1 response code bit.
    /// </summary>
    RC_FMT1 = 0x080,

    /// <summary>
    /// TPM_RC_ASYMMETRIC: Asymmetric algorithm not supported or not correct.
    /// </summary>
    TPM_RC_ASYMMETRIC = 0x081,

    /// <summary>
    /// TPM_RC_ATTRIBUTES: Inconsistent attributes.
    /// </summary>
    TPM_RC_ATTRIBUTES = 0x082,

    /// <summary>
    /// TPM_RC_HASH: Hash algorithm not supported or not appropriate.
    /// </summary>
    TPM_RC_HASH = 0x083,

    /// <summary>
    /// TPM_RC_VALUE: Value is out of range or is not correct for the context.
    /// </summary>
    TPM_RC_VALUE = 0x084,

    /// <summary>
    /// TPM_RC_HIERARCHY: Hierarchy is not enabled or is not correct for the use.
    /// </summary>
    TPM_RC_HIERARCHY = 0x085,

    /// <summary>
    /// TPM_RC_KEY_SIZE: Key size is not supported.
    /// </summary>
    TPM_RC_KEY_SIZE = 0x087,

    /// <summary>
    /// TPM_RC_MGF: Mask generation function not supported.
    /// </summary>
    TPM_RC_MGF = 0x088,

    /// <summary>
    /// TPM_RC_MODE: Mode of operation not supported.
    /// </summary>
    TPM_RC_MODE = 0x089,

    /// <summary>
    /// TPM_RC_TYPE: The type of the value is not appropriate for the use.
    /// </summary>
    TPM_RC_TYPE = 0x08A,

    /// <summary>
    /// TPM_RC_HANDLE: The handle is not correct for the use.
    /// </summary>
    TPM_RC_HANDLE = 0x08B,

    /// <summary>
    /// TPM_RC_KDF: Unsupported key derivation function or function not appropriate for use.
    /// </summary>
    TPM_RC_KDF = 0x08C,

    /// <summary>
    /// TPM_RC_RANGE: Value was out of allowed range.
    /// </summary>
    TPM_RC_RANGE = 0x08D,

    /// <summary>
    /// TPM_RC_AUTH_FAIL: The authorization HMAC check failed and DA counter incremented.
    /// </summary>
    TPM_RC_AUTH_FAIL = 0x08E,

    /// <summary>
    /// TPM_RC_NONCE: Invalid nonce size or nonce value mismatch.
    /// </summary>
    TPM_RC_NONCE = 0x08F,

    /// <summary>
    /// TPM_RC_PP: Authorization requires assertion of PP.
    /// </summary>
    TPM_RC_PP = 0x090,

    /// <summary>
    /// TPM_RC_SCHEME: Unsupported or incompatible scheme.
    /// </summary>
    TPM_RC_SCHEME = 0x092,

    /// <summary>
    /// TPM_RC_SIZE: Structure is the wrong size.
    /// </summary>
    TPM_RC_SIZE = 0x095,

    /// <summary>
    /// TPM_RC_SYMMETRIC: Unsupported symmetric algorithm or key size, or not appropriate for instance.
    /// </summary>
    TPM_RC_SYMMETRIC = 0x096,

    /// <summary>
    /// TPM_RC_TAG: Incorrect structure tag.
    /// </summary>
    TPM_RC_TAG = 0x097,

    /// <summary>
    /// TPM_RC_SELECTOR: Union selector is incorrect.
    /// </summary>
    TPM_RC_SELECTOR = 0x098,

    /// <summary>
    /// TPM_RC_INSUFFICIENT: The TPM was unable to unmarshal a value because there were not enough octets in the input buffer.
    /// </summary>
    TPM_RC_INSUFFICIENT = 0x09A,

    /// <summary>
    /// TPM_RC_SIGNATURE: The signature is not valid.
    /// </summary>
    TPM_RC_SIGNATURE = 0x09B,

    /// <summary>
    /// TPM_RC_KEY: Key fields are not compatible with the selected use.
    /// </summary>
    TPM_RC_KEY = 0x09C,

    /// <summary>
    /// TPM_RC_POLICY_FAIL: A policy check failed.
    /// </summary>
    TPM_RC_POLICY_FAIL = 0x09D,

    /// <summary>
    /// TPM_RC_INTEGRITY: Integrity check failed.
    /// </summary>
    TPM_RC_INTEGRITY = 0x09F,

    /// <summary>
    /// TPM_RC_TICKET: Invalid ticket.
    /// </summary>
    TPM_RC_TICKET = 0x0A0,

    /// <summary>
    /// TPM_RC_RESERVED_BITS: Reserved bits not set to zero as required.
    /// </summary>
    TPM_RC_RESERVED_BITS = 0x0A1,

    /// <summary>
    /// TPM_RC_BAD_AUTH: Authorization failure without DA implications.
    /// </summary>
    TPM_RC_BAD_AUTH = 0x0A2,

    /// <summary>
    /// TPM_RC_EXPIRED: The policy has expired.
    /// </summary>
    TPM_RC_EXPIRED = 0x0A3,

    /// <summary>
    /// TPM_RC_POLICY_CC: The commandCode in the policy is not the commandCode of the command or the command code in a policy command references a command that is not implemented.
    /// </summary>
    TPM_RC_POLICY_CC = 0x0A4,

    /// <summary>
    /// TPM_RC_BINDING: Public and sensitive portions of an object are not cryptographically bound.
    /// </summary>
    TPM_RC_BINDING = 0x0A5,

    /// <summary>
    /// TPM_RC_CURVE: Curve not supported.
    /// </summary>
    TPM_RC_CURVE = 0x0A6,

    /// <summary>
    /// TPM_RC_ECC_POINT: Point is not on the required curve.
    /// </summary>
    TPM_RC_ECC_POINT = 0x0A7,

    /// <summary>
    /// RC_WARN: Set for warning response codes.
    /// </summary>
    RC_WARN = 0x900,

    /// <summary>
    /// TPM_RC_CONTEXT_GAP: Gap for context ID is too large.
    /// </summary>
    TPM_RC_CONTEXT_GAP = 0x901,

    /// <summary>
    /// TPM_RC_OBJECT_MEMORY: Out of memory for object contexts.
    /// </summary>
    TPM_RC_OBJECT_MEMORY = 0x902,

    /// <summary>
    /// TPM_RC_SESSION_MEMORY: Out of memory for session contexts.
    /// </summary>
    TPM_RC_SESSION_MEMORY = 0x903,

    /// <summary>
    /// TPM_RC_MEMORY: Out of shared object/session memory or need space for internal operations.
    /// </summary>
    TPM_RC_MEMORY = 0x904,

    /// <summary>
    /// TPM_RC_SESSION_HANDLES: Out of session handles.
    /// </summary>
    TPM_RC_SESSION_HANDLES = 0x905,

    /// <summary>
    /// TPM_RC_OBJECT_HANDLES: Out of object handles.
    /// </summary>
    TPM_RC_OBJECT_HANDLES = 0x906,

    /// <summary>
    /// TPM_RC_LOCALITY: Bad locality.
    /// </summary>
    TPM_RC_LOCALITY = 0x907,

    /// <summary>
    /// TPM_RC_YIELDED: The TPM has suspended operation on the command; forward progress was made and the command may be retried.
    /// </summary>
    TPM_RC_YIELDED = 0x908,

    /// <summary>
    /// TPM_RC_CANCELED: The command was canceled.
    /// </summary>
    TPM_RC_CANCELED = 0x909,

    /// <summary>
    /// TPM_RC_TESTING: TPM is performing self-tests.
    /// </summary>
    TPM_RC_TESTING = 0x90A,

    /// <summary>
    /// TPM_RC_REFERENCE_H0: The 1st handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H0 = 0x910,

    /// <summary>
    /// TPM_RC_REFERENCE_H1: The 2nd handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H1 = 0x911,

    /// <summary>
    /// TPM_RC_REFERENCE_H2: The 3rd handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H2 = 0x912,

    /// <summary>
    /// TPM_RC_REFERENCE_H3: The 4th handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H3 = 0x913,

    /// <summary>
    /// TPM_RC_REFERENCE_H4: The 5th handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H4 = 0x914,

    /// <summary>
    /// TPM_RC_REFERENCE_H5: The 6th handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H5 = 0x915,

    /// <summary>
    /// TPM_RC_REFERENCE_H6: The 7th handle in the handle area references a transient object or session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_H6 = 0x916,

    /// <summary>
    /// TPM_RC_REFERENCE_S0: The 1st authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S0 = 0x918,

    /// <summary>
    /// TPM_RC_REFERENCE_S1: The 2nd authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S1 = 0x919,

    /// <summary>
    /// TPM_RC_REFERENCE_S2: The 3rd authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S2 = 0x91A,

    /// <summary>
    /// TPM_RC_REFERENCE_S3: The 4th authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S3 = 0x91B,

    /// <summary>
    /// TPM_RC_REFERENCE_S4: The 5th authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S4 = 0x91C,

    /// <summary>
    /// TPM_RC_REFERENCE_S5: The 6th authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S5 = 0x91D,

    /// <summary>
    /// TPM_RC_REFERENCE_S6: The 7th authorization session handle references a session that is not loaded.
    /// </summary>
    TPM_RC_REFERENCE_S6 = 0x91E,

    /// <summary>
    /// TPM_RC_NV_RATE: The TPM is rate-limiting accesses to prevent wearout of NV.
    /// </summary>
    TPM_RC_NV_RATE = 0x920,

    /// <summary>
    /// TPM_RC_LOCKOUT: Authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode.
    /// </summary>
    TPM_RC_LOCKOUT = 0x921,

    /// <summary>
    /// TPM_RC_RETRY: The TPM was not able to start the command.
    /// </summary>
    TPM_RC_RETRY = 0x922,

    /// <summary>
    /// TPM_RC_NV_UNAVAILABLE: The command may require writing of NV and NV is not current accessible.
    /// </summary>
    TPM_RC_NV_UNAVAILABLE = 0x923
}

/// <summary>
/// Extension methods for TPM response code handling.
/// </summary>
public static class TpmRcExtensions
{
    /// <summary>
    /// Gets a human-readable description of the TPM response code.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>A description of the error, or the hex code if unknown.</returns>
    public static string GetDescription(this TpmRc rc)
    {
        return rc switch
        {
            TpmRc.Success => "Command completed successfully.",
            TpmRc.TPM_RC_BAD_TAG => "Undefined tag in command header.",
            TpmRc.TPM_RC_INITIALIZE => "TPM not initialized by TPM2_Startup or already initialized.",
            TpmRc.Failure => "Commands not being accepted because of a TPM failure.",
            TpmRc.TPM_RC_SEQUENCE => "Improper use of a sequence handle.",
            TpmRc.TPM_RC_DISABLED => "The command is disabled.",
            TpmRc.TPM_RC_EXCLUSIVE => "Command failed because audit sequence required exclusivity.",
            TpmRc.TPM_RC_AUTH_TYPE => "Authorization handle is not correct for command.",
            TpmRc.TPM_RC_AUTH_MISSING => "Command requires an authorization session for handle and it is not present.",
            TpmRc.TPM_RC_POLICY => "Policy failure in math operation or invalid authPolicy value.",
            TpmRc.TPM_RC_PCR => "Platform Configuration Register (PCR) check failed.",
            TpmRc.TPM_RC_PCR_CHANGED => "Platform Configuration Registers (PCR) have changed since checked.",
            TpmRc.TPM_RC_COMMAND_SIZE => "Command commandSize value is inconsistent with contents of the command buffer.",
            TpmRc.TPM_RC_COMMAND_CODE => "Command code not supported.",
            TpmRc.TPM_RC_AUTHSIZE => "The value of authorizationSize is out of range.",
            TpmRc.TPM_RC_NV_LOCKED => "Non-Volatile (NV) memory access locked.",
            TpmRc.TPM_RC_NV_AUTHORIZATION => "Non-Volatile (NV) memory access authorization fails in command actions.",
            TpmRc.TPM_RC_NV_UNINITIALIZED => "A Non-Volatile (NV) Index is used before being initialized.",
            TpmRc.TPM_RC_NV_SPACE => "Insufficient space for Non-Volatile (NV) memory allocation.",
            TpmRc.TPM_RC_NV_DEFINED => "Non-Volatile (NV) Index or persistent object already defined.",
            TpmRc.TPM_RC_ASYMMETRIC => "Asymmetric algorithm not supported or not correct.",
            TpmRc.TPM_RC_ATTRIBUTES => "Inconsistent attributes.",
            TpmRc.TPM_RC_HASH => "Hash algorithm not supported or not appropriate.",
            TpmRc.TPM_RC_VALUE => "Value is out of range or is not correct for the context.",
            TpmRc.TPM_RC_HIERARCHY => "Hierarchy is not enabled or is not correct for the use.",
            TpmRc.TPM_RC_KEY_SIZE => "Key size is not supported.",
            TpmRc.TPM_RC_MGF => "Mask Generation Function (MGF) not supported.",
            TpmRc.TPM_RC_MODE => "Mode of operation not supported.",
            TpmRc.TPM_RC_TYPE => "The type of the value is not appropriate for the use.",
            TpmRc.TPM_RC_HANDLE => "The handle is not correct for the use.",
            TpmRc.TPM_RC_KDF => "Unsupported Key Derivation Function (KDF).",
            TpmRc.TPM_RC_RANGE => "Value was out of allowed range.",
            TpmRc.TPM_RC_AUTH_FAIL => "The authorization Hash-based Message Authentication Code (HMAC) check failed and Dictionary Attack (DA) counter incremented.",
            TpmRc.TPM_RC_NONCE => "Invalid nonce size or nonce value mismatch.",
            TpmRc.TPM_RC_PP => "Authorization requires assertion of Physical Presence (PP).",
            TpmRc.TPM_RC_SCHEME => "Unsupported or incompatible scheme.",
            TpmRc.TPM_RC_SIZE => "Structure is the wrong size.",
            TpmRc.TPM_RC_SYMMETRIC => "Unsupported symmetric algorithm or key size.",
            TpmRc.TPM_RC_TAG => "Incorrect structure tag.",
            TpmRc.TPM_RC_SELECTOR => "Union selector is incorrect.",
            TpmRc.TPM_RC_INSUFFICIENT => "Not enough octets in the input buffer.",
            TpmRc.TPM_RC_SIGNATURE => "The signature is not valid.",
            TpmRc.TPM_RC_KEY => "Key fields are not compatible with the selected use.",
            TpmRc.TPM_RC_POLICY_FAIL => "A policy check failed.",
            TpmRc.TPM_RC_INTEGRITY => "Integrity check failed.",
            TpmRc.TPM_RC_BAD_AUTH => "Authorization failure without Dictionary Attack (DA) implications.",
            TpmRc.TPM_RC_EXPIRED => "The policy has expired.",
            TpmRc.TPM_RC_CURVE => "Elliptic curve not supported.",
            TpmRc.TPM_RC_ECC_POINT => "Point is not on the required Elliptic Curve Cryptography (ECC) curve.",
            TpmRc.TPM_RC_CONTEXT_GAP => "Gap for context ID is too large.",
            TpmRc.TPM_RC_OBJECT_MEMORY => "Out of memory for object contexts.",
            TpmRc.TPM_RC_SESSION_MEMORY => "Out of memory for session contexts.",
            TpmRc.TPM_RC_MEMORY => "Out of shared object/session memory.",
            TpmRc.TPM_RC_SESSION_HANDLES => "Out of session handles.",
            TpmRc.TPM_RC_OBJECT_HANDLES => "Out of object handles.",
            TpmRc.TPM_RC_LOCALITY => "Bad locality.",
            TpmRc.TPM_RC_YIELDED => "The TPM has suspended operation on the command.",
            TpmRc.TPM_RC_CANCELED => "The command was canceled.",
            TpmRc.TPM_RC_TESTING => "TPM is performing self-tests.",
            TpmRc.TPM_RC_NV_RATE => "The TPM is rate-limiting accesses to prevent wearout of Non-Volatile (NV) memory.",
            TpmRc.TPM_RC_LOCKOUT => "Authorizations for objects subject to Dictionary Attack (DA) protection are not allowed (TPM is in DA lockout mode).",
            TpmRc.TPM_RC_RETRY => "The TPM was not able to start the command.",
            TpmRc.TPM_RC_NV_UNAVAILABLE => "The command may require writing of Non-Volatile (NV) memory and NV is not currently accessible.",
            _ => $"Unknown TPM error: 0x{(uint)rc:X8}"
        };
    }

    /// <summary>
    /// Formats the response code as a string with name and description.
    /// </summary>
    /// <param name="rc">The TPM response code.</param>
    /// <returns>A formatted string like "TPM_RC_HASH (0x083): Hash algorithm not supported or not appropriate."</returns>
    public static string Format(this TpmRc rc)
    {
        string name = Enum.IsDefined(rc) ? rc.ToString() : "UNKNOWN";
        return $"{name} (0x{(uint)rc:X3}): {rc.GetDescription()}";
    }
}