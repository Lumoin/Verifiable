using System;

namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_PS constants (Table 32).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 32).
/// </para>
/// </remarks>
public enum TpmPsConstants : uint
{
    /// <summary>
    /// not platform specific
    /// </summary>
    TPM_PS_MAIN = 0x00000000,

    /// <summary>
    /// Client
    /// </summary>
    TPM_PS_PC = 0x00000001,

    /// <summary>
    /// (includes all mobile devices that are not specifically cell phones)
    /// </summary>
    TPM_PS_PDA = 0x00000002,

    /// <summary>
    /// Cell Phone
    /// </summary>
    TPM_PS_CELL_PHONE = 0x00000003,

    /// <summary>
    /// Server WG
    /// </summary>
    TPM_PS_SERVER = 0x00000004,

    /// <summary>
    /// Peripheral WG
    /// </summary>
    TPM_PS_PERIPHERAL = 0x00000005,

    /// <summary>
    /// (deprecated)
    /// </summary>
    TPM_PS_TSS = 0x00000006,

    /// <summary>
    /// Storage WG
    /// </summary>
    TPM_PS_STORAGE = 0x00000007,

    /// <summary>
    /// Authentication WG
    /// </summary>
    TPM_PS_AUTHENTICATION = 0x00000008,

    /// <summary>
    /// Embedded WG
    /// </summary>
    TPM_PS_EMBEDDED = 0x00000009,

    /// <summary>
    /// Hardcopy WG
    /// </summary>
    TPM_PS_HARDCOPY = 0x0000000A,

    /// <summary>
    /// Infrastructure WG (deprecated)
    /// </summary>
    TPM_PS_INFRASTRUCTURE = 0x0000000B,

    /// <summary>
    /// Virtualization WG
    /// </summary>
    TPM_PS_VIRTUALIZATION = 0x0000000C,

    /// <summary>
    /// Trusted Network Connect WG (deprecated)
    /// </summary>
    TPM_PS_TNC = 0x0000000D,

    /// <summary>
    /// Multi-tenant WG (deprecated)
    /// </summary>
    TPM_PS_MULTI_TENANT = 0x0000000E,

    /// <summary>
    /// Technical Committee (deprecated)
    /// </summary>
    TPM_PS_TC = 0x0000000F
}