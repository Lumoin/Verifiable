namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM 2.0 capability categories (TPM_CAP) for use with TPM2_GetCapability.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 6.12 - TPM_CAP.
/// </para>
/// </remarks>
public enum Tpm2CapConstants: uint
{
    /// <summary>
    /// TPM_CAP_FIRST: First capability value (same as TPM_CAP_ALGS).
    /// </summary>
    TPM_CAP_FIRST = 0x00000000,

    /// <summary>
    /// TPM_CAP_ALGS: List of supported algorithms with their properties.
    /// </summary>
    TPM_CAP_ALGS = 0x00000000,

    /// <summary>
    /// TPM_CAP_HANDLES: List of all handles of a given type currently loaded.
    /// </summary>
    TPM_CAP_HANDLES = 0x00000001,

    /// <summary>
    /// TPM_CAP_COMMANDS: List of supported commands with their properties.
    /// </summary>
    TPM_CAP_COMMANDS = 0x00000002,

    /// <summary>
    /// TPM_CAP_PP_COMMANDS: List of commands that require physical presence for authorization.
    /// </summary>
    TPM_CAP_PP_COMMANDS = 0x00000003,

    /// <summary>
    /// TPM_CAP_AUDIT_COMMANDS: List of commands currently being audited.
    /// </summary>
    TPM_CAP_AUDIT_COMMANDS = 0x00000004,

    /// <summary>
    /// TPM_CAP_PCRS: List of PCRs with their current digest values.
    /// </summary>
    TPM_CAP_PCRS = 0x00000005,

    /// <summary>
    /// TPM_CAP_TPM_PROPERTIES: List of TPM properties (fixed and variable).
    /// </summary>
    TPM_CAP_TPM_PROPERTIES = 0x00000006,

    /// <summary>
    /// TPM_CAP_PCR_PROPERTIES: List of PCR properties.
    /// </summary>
    TPM_CAP_PCR_PROPERTIES = 0x00000007,

    /// <summary>
    /// TPM_CAP_ECC_CURVES: List of supported ECC curves.
    /// </summary>
    TPM_CAP_ECC_CURVES = 0x00000008,

    /// <summary>
    /// TPM_CAP_AUTH_POLICIES: List of authorization policies for permanent handles.
    /// </summary>
    TPM_CAP_AUTH_POLICIES = 0x00000009,

    /// <summary>
    /// TPM_CAP_ACT: List of Authenticated Countdown Timers.
    /// </summary>
    TPM_CAP_ACT = 0x0000000A,

    /// <summary>
    /// TPM_CAP_LAST: Last defined capability value.
    /// </summary>
    TPM_CAP_LAST = 0x0000000A,

    /// <summary>
    /// TPM_CAP_VENDOR_PROPERTY: Vendor-specific capability.
    /// </summary>
    TPM_CAP_VENDOR_PROPERTY = 0x00000100
}