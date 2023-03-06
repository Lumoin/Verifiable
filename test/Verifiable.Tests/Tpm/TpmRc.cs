namespace Verifiable.Tpm
{
    /// <summary>
    /// TPM_RC: Enumeration of TPM response codes defined in the TPM 2.0 specification (Part 2).
    /// </summary>
    /// <remarks>Each return from the TPM has a 32-bit response code.The TPM will always set the upper 20 bits(31:12)
    /// of the response code to 0 00 0016 and the low-order 12 bits(11:00) will contain the response code.
    /// When a command succeeds, the TPM shall return TPM_RC_SUCCESS(0 0016) and will update any
    /// authorization-session nonce associated with the command.    
    /// See more at <see href="https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf">TPM_RC_COMMAND_CODE in TPM 2.0 specification (Part 2)</see>.    
    /// </remarks>
    public enum TpmRc: uint
    {
        /// <summary>Response code for successful completion of the command.</summary>
        Success = 0x000,

        /// <summary>The one (1) is added to an RC_VER1 response code to make it unique.</summary>        
        Ver1 = 0x100,

        /// <summary>The TPM is not initialized by TPM2_Startup or already initialized.</summary>        
        Initialize = Ver1 + 0x000,

        /// <summary>The TPM has suffered a failure that prevents it from executing the command.</summary>        
        Failure = Ver1 + 0x001,

        /// <summary>The command code is not supported.</summary>        
        Sequence = Ver1 + 0x003,

        /// <summary>Not currently used.</summary>        
        Private = Ver1 + 0x00B,

        /// <summary>Not currently used.</summary>        
        Hmac = Ver1 + 0x019,

        /// <summary>The command is disabled.</summary>        
        Disabled = Ver1 + 0x020,

        /// <summary>The command or the object is not available for the exclusive use of the caller.</summary>        
        Exclusive = Ver1 + 0x021,

        /// <summary>The authorization HMAC check failed and DA counter incremented.</summary>        
        AuthType = Ver1 + 0x024,

        /// <summary>The command requires an authorization session for handle and it is not present.</summary>        
        AuthMissing = Ver1 + 0x025,

        /// <summary>The policy for the object is not available or the object does not have a policy.</summary>        
        Policy = Ver1 + 0x026,

        /// <summary>The PCR is not available or the PCR does not have a policy.</summary>        
        Pcr = Ver1 + 0x027,

        /// <summary>The PCR value changed between command actions.</summary>        
        PcrChanged = Ver1 + 0x028,

        /// <summary>The TPM is in field upgrade mode.</summary>        
        Upgrade = Ver1 + 0x02D,

        /// <summary>There are too many context stored on the TPM.</summary>        
        TooManyContexts = Ver1 + 0x02E,

        /// <summary>The authValue or authPolicy is not available for the selected entity.</summary>        
        AuthUnavailable = Ver1 + 0x02F,

        /// <summary>The TPM is in a state where it requires a power cycle (TPM reset) to recover.</summary>        
        Reboot = Ver1 + 0x030,

        /// <summary>An NV Index or persistent object requires one or more authorizations, and the TPM_RC_AUTH_MISSING error code would be returned if an authorization was missing; however, none of the authorization values can be TPM_RH_NULL.</summary>        
        Unbalanced = Ver1 + 0x031,

        /// <summary>The command buffer is too short to contain a properly formed command.</summary>
        CommandSize = Ver1 + 0x042,

        /// <summary>The command code is not supported.</summary>        
        CommandCode = Ver1 + 0x043,

        /// <summary>The authValue buffer is not properly formed.</summary>        
        AuthSize = Ver1 + 0x044,

        /// <summary>The authorization session is not properly formed.</summary>        
        AuthContext = Ver1 + 0x045,

        /// <summary>The NV Index is not within the allowed range of values.</summary>        
        NvRange = Ver1 + 0x046,

        /// <summary>The NV Index has insufficient space remaining for the data.</summary>        
        NvSize = Ver1 + 0x047,

        /// <summary>The NV Index is locked (read/write) and the command is not a read.</summary>        
        NvLocked = Ver1 + 0x048,

        /// <summary>The NV Index authorization is not correct for the command.</summary>        
        NvAuthorization = Ver1 + 0x049,

        /// <summary>The NV Index has not been initialized (written).</summary>        
        NvUnitialized = Ver1 + 0x04A,

        /// <summary>There is insufficient space in NV memory for the operation.</summary>        
        NvSpace = Ver1 + 0x04B,

        /// <summary>The NV Index is already defined.</summary>        
        NvDefined = Ver1 + 0x04C,

        /// <summary>The context handle does not match any known context.</summary>        
        BadContext = Ver1 + 0x050,

        /// <summary>The cpHash value does not match the expected value.</summary>        
        CpHash = Ver1 + 0x051,

        /// <summary>The parent handle does not match the parent in the TPM2B_PRIVATE.</summary>        
        Parent = Ver1 + 0x052,

        /// <summary>Some function needs testing on this TPM, but the test has not been run.</summary>        
        NeedsTest = Ver1 + 0x053,

        /// <summary>No result is returned by the function.</summary>        
        NoResult = Ver1 + 0x054,

        /// <summary>The TPM returned a sensitive value.</summary>        
        Sensitive = Ver1 + 0x055,

        /// <summary>The maximum value for the F0 error codes.</summary>        
        MaxFm0 = Ver1 + 0x07F,

        /// <summary>The base value for the F1 error codes.</summary>        
        Fmt1 = 0x080,

        /// <summary>An asymmetric algorithm is not correct for the intended use.</summary>        
        Asymmetric = Fmt1 + 0x001,

        /// <summary>Incorrect attributes for the entity.</summary>        
        Attributes = Fmt1 + 0x002,

        /// <summary>The hash algorithm is not supported or not appropriate.</summary>        
        Hash = Fmt1 + 0x003,

        /// <summary>The value is out of range or the relationship between values is not correct.</summary>        
        Value = Fmt1 + 0x004,

        /// <summary>The selected authorization hierarchy is not allowed for the operation.</summary>        
        Hierarchy = Fmt1 + 0x005,

        /// <summary>The key size is not supported.</summary>        
        KeySize = Fmt1 + 0x007,

        /// <summary>Incorrect Mask Generation Function (MGF) was selected.</summary>        
        Mgf = Fmt1 + 0x008,

        /// <summary>Incorrect mode value for a mode-dependent parameter.</summary>        
        Mode = Fmt1 + 0x009,

        /// <summary>Incorrect object type for the operation.</summary>        
        Type = Fmt1 + 0x00A,

        /// <summary>Incorrect handle usage for the operation.</summary>        
        Handle = Fmt1 + 0x00B,

        /// <summary>Incorrect Key Derivation Function (KDF) was selected.</summary>        
        Kdf = Fmt1 + 0x00C,

        /// <summary>A value is out of its allowed range.</summary>        
        Range = Fmt1 + 0x00D,

        /// <summary>Authorization failure without a DA implication.</summary>        
        AuthFail = Fmt1 + 0x00E,

        /// <summary>Invalid nonce size or nonce value mismatch.</summary>        
        Nonce = Fmt1 + 0x00F,

        /// <summary>Authorization requires assertion of PP.</summary>        
        Pp = Fmt1 + 0x010,

        /// <summary>Incorrect or inconsistent scheme.</summary>        
        Scheme = Fmt1 + 0x012,

        /// <summary>Incorrect or inconsistent size value.</summary>        
        Size = Fmt1 + 0x015,

        /// <summary>Incorrect or inconsistent symmetric algorithm.</summary>        
        SYMMETRIC = Fmt1 + 0x016,

        /// <summary>Incorrect or inconsistent tag value.</summary>        
        TAG = Fmt1 + 0x017,

        /// <summary>Incorrect structure tag for an RSA key.</summary>        
        SELECTOR = Fmt1 + 0x018,

        /// <summary>The signature is valid but the signer does not have the proper authority to sign the data.</summary>        
        INSUFFICIENT = Fmt1 + 0x01A,

        /// <summary>Invalid signature.</summary>        
        SIGNATURE = Fmt1 + 0x01B,

        /// <summary>Key fields are not compatible with the selected use.</summary>        
        KEY = Fmt1 + 0x01C,

        /// <summary>A policy check failed and DA counter incremented.</summary>        
        POLICY_FAIL = Fmt1 + 0x01D,

        /// <summary>Integrity check failed.</summary>        
        INTEGRITY = Fmt1 + 0x01F,

        /// <summary>Invalid ticket.</summary>        
        TICKET = Fmt1 + 0x020,

        /// <summary>Reserved bits not set to zero as required.</summary>        
        RESERVED_BITS = Fmt1 + 0x021,

        /// <summary>Incorrect authorization.</summary>        
        BAD_AUTH = Fmt1 + 0x022,

        /// <summary>The policy has expired.</summary>        
        EXPIRED = Fmt1 + 0x023,

        /// <summary>The command code in the policy is not the command code of the command or the command code in a policy command.</summary>        
        POLICY_CC = Fmt1 + 0x024,

        /// <summary>Public and sensitive portions of an object are not cryptographically bound.</summary>        
        BINDING = Fmt1 + 0x025,

        /// <summary>Unsupported or incompatible elliptic curve.</summary>        
        CURVE = Fmt1 + 0x026,

        /// <summary>Bad point on an elliptic curve.</summary>        
        ECC_POINT = Fmt1 + 0x027,

        /// <summary>This is a warning level with the value of the lowest warning code.</summary>
        WARN = 0x900,

        /// <summary>The gap between saved context counts is too large.</summary>        
        CONTEXT_GAP = WARN + 0x001,

        /// <summary>Out of memory for object contexts.</summary>        
        OBJECT_MEMORY = WARN + 0x002,

        /// <summary>Out of memory for session contexts.</summary>        
        SESSION_MEMORY = WARN + 0x003,

        /// <summary>Out of shared object/session memory or need space for internal operations.</summary>        
        MEMORY = WARN + 0x004,

        /// <summary>Out of session handles; a session must be deleted before a new one can be created.</summary>        
        SESSION_HANDLES = WARN + 0x005,

        /// <summary>Out of object handles; a reboot might be necessary.</summary>        
        OBJECT_HANDLES = WARN + 0x006,

        /// <summary>Bad locality.</summary>        
        LOCALITY = WARN + 0x007,

        /// <summary>The TPM has suspended operation on the command; forward progress was made, and the command may be retried.</summary>        
        YIELDED = WARN + 0x008,

        /// <summary>The command was canceled.</summary>        
        CANCELED = WARN + 0x009,

        /// <summary>TPM is performing self-tests.</summary>        
        TESTING = WARN + 0x00A,

        /// <summary>The 1st handle in the handle area references a transient object or session that is not loaded.</summary>        
        REFERENCE_H0 = WARN + 0x010,

        /// <summary>The 2nd handle in the handle area references a transient object or session that is not loaded.</summary>        
        REFERENCE_H1 = WARN + 0x011,

        /// <summary>The 3rd handle in the handle area references a transient object or session that is not loaded.</summary>        
        REFERENCE_H2 = WARN + 0x012,

        /// <summary>The 4th handle in the handle area references a transient object or session that is not loaded.</summary>        
        REFERENCE_H3 = WARN + 0x013,

        /// <summary>The 5th handle in the handle area references a transient object or session that is not loaded.</summary>        
        REFERENCE_H4 = WARN + 0x014,

        /// <summary>The 6th handle in the handle area references a transient object or session that is not loaded.</summary>        
        REFERENCE_H5 = WARN + 0x015,

        /// <summary>The 7th handle in the handle area references a transient object or session that is not loaded.</summary>        
        REFERENCE_H6 = WARN + 0x016,

        /// <summary>The 1st authorization session handle references a session that is not loaded.</summary>        
        REFERENCE_S0 = WARN + 0x018,

        /// <summary>The 2nd authorization session handle references a session that is not loaded.</summary>        
        REFERENCE_S1 = WARN + 0x019,

        /// <summary>The 3rd authorization session handle references a session that is not loaded.</summary>        
        REFERENCE_S2 = WARN + 0x01A,

        /// <summary>The 4th authorization session handle references a session that is not loaded.</summary>        
        REFERENCE_S3 = WARN + 0x01B,

        /// <summary>The 5th authorization session handle references a session that is not loaded.</summary>        
        REFERENCE_S4 = WARN + 0x01C,

        /// <summary>The 6th authorization session handle references a session that is not loaded.</summary>        
        REFERENCE_S5 = WARN + 0x01D,

        /// <summary>The 7th authorization session handle references a session that is not loaded.</summary>        
        REFERENCE_S6 = WARN + 0x01E,

        /// <summary>The TPM is too busy to respond to the command because of the rate of incoming commands.</summary>        
        NV_RATE = WARN + 0x020,

        /// <summary>The command may require writing of NV, and NV is not available for writing.</summary>        
        LOCKOUT = WARN + 0x021,

        /// <summary>The command had a retry handle, but the command was not a retry.</summary>        
        RETRY = WARN + 0x022,

        /// <summary>An NV Index is locked and must be unlocked before it may be used.</summary>        
        NV_UNAVAILABLE = WARN + 0x023,

        /// <summary>This value is never returned from the TPM and is used as a place holder to simplify handling of TPM2_RC_WARN codes.</summary>        
        NOT_USED = WARN + 0x7F,

        /// <summary>Used to shift an RC level to the position of the H field in the response code.</summary>        
        H = 0x000,

        /// <summary>Used to shift an RC level to the position of the P field in the response code.</summary>        
        P = 0x040,

        /// <summary>Used to shift an RC level to the position of the S field in the response code.</summary>        
        S = 0x800,

        /// <summary>Used to shift an RC level to the position of the 1 field in the response code.</summary>        
        _1 = 0x100,

        /// <summary>Used to shift an RC level to the position of the 2 field in the response code.</summary>        
        _2 = 0x200,

        /// <summary>Used to shift an RC level to the position of the 3 field in the response code.</summary>        
        _3 = 0x300,

        /// <summary>Used to shift an RC level to the position of the 4 field in the response code.</summary>        
        _4 = 0x400,

        /// <summary>Used to shift an RC level to the position of the 5 field in the response code.</summary>        
        _5 = 0x500,

        /// <summary>Used to shift an RC level to the position of the 6 field in the response code.</summary>        
        _6 = 0x600,

        /// <summary>Used to shift an RC level to the position of the 7 field in the response code.</summary>        
        _7 = 0x700,

        /// <summary>Used to shift an RC level to the position of the 8 field in the response code.</summary>        
        _8 = 0x800,

        /// <summary>Used to shift an RC level to the position of the 9 field in the response code.</summary>        
        _9 = 0x900,

        /// <summary>Used to shift an RC level to the position of the A field in the response code.</summary>        
        A = 0xA00,

        /// <summary>Used to shift an RC level to the position of the B field in the response code.</summary>        
        B = 0xB00,

        /// <summary>Used to shift an RC level to the position of the C field in the response code.</summary>        
        C = 0xC00,

        /// <summary>Used to shift an RC level to the position of the D field in the response code.</summary>        
        D = 0xD00,

        /// <summary>Used to shift an RC level to the position of the E field in the response code.</summary>        
        E = 0xE00,

        /// <summary>Used to shift an RC level to the position of the F field in the response code.</summary>        
        F = 0xF00,

        /// <summary>Used to set or clear the N field in the response code.</summary>        
        N_MASK = 0xF00
    }
}
