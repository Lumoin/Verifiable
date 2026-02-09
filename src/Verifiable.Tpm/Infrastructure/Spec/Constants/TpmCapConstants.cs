using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Structures.Spec.Constants;

/// <summary>
/// TPM_CAP constants (Table 26).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 26).
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1069:Enums values should not be duplicated", Justification = "TPM 2.0 specification allows duplicate values for compatibility and other reasons.")]
[SuppressMessage("Design", "CA1027:Mark enums with FlagsAttribute", Justification = "TPM 2.0 specification does not define these as flags.")]
public enum TpmCapConstants: uint
{
    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_CAP_FIRST = 0x00000000,

    /// <summary>
    /// TPM_ALG_ID (1) TPML_ALG_PROPERTY
    /// </summary>
    TPM_CAP_ALGS = 0x00000000,

    /// <summary>
    /// TPM_HANDLE TPML_HANDLE
    /// </summary>
    TPM_CAP_HANDLES = 0x00000001,

    /// <summary>
    /// TPM_CC TPML_CCA
    /// </summary>
    TPM_CAP_COMMANDS = 0x00000002,

    /// <summary>
    /// TPM_CC TPML_CC
    /// </summary>
    TPM_CAP_PP_COMMANDS = 0x00000003,

    /// <summary>
    /// TPM_CC TPML_CC
    /// </summary>
    TPM_CAP_AUDIT_COMMANDS = 0x00000004,

    /// <summary>
    /// reserved TPML_PCR_SELECTION
    /// </summary>
    TPM_CAP_PCRS = 0x00000005,

    /// <summary>
    /// TPM_PT TPML_TAGGED_TPM_PROPERTY
    /// </summary>
    TPM_CAP_TPM_PROPERTIES = 0x00000006,

    /// <summary>
    /// TPM_PT_PCR TPML_TAGGED_PCR_PROPERTY Capability Name Value Property Type Return Type
    /// </summary>
    TPM_CAP_PCR_PROPERTIES = 0x00000007,

    /// <summary>
    /// TPM_ECC_CURVE TPML_ECC_CURVE (1)
    /// </summary>
    TPM_CAP_ECC_CURVES = 0x00000008,

    /// <summary>
    /// TPM_HANDLE (2) TPML_TAGGED_POLICY (3)
    /// </summary>
    TPM_CAP_AUTH_POLICIES = 0x00000009,

    /// <summary>
    /// TPM_HANDLE (2) TPML_ACT_DATA (4)
    /// </summary>
    TPM_CAP_ACT = 0x0000000A,

    /// <summary>
    /// TPM_PUB_KEY TPML_PUB_KEY (5)
    /// </summary>
    TPM_CAP_PUB_KEYS = 0x0000000B,

    /// <summary>
    /// reserved (5) TPML_SPDM_SESSION_INFO
    /// </summary>
    TPM_CAP_SPDM_SESSION_INFO = 0x0000000C,

    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_CAP_LAST = 0x0000000C,

    /// <summary>
    /// manufacturer manufacturer-specific values specific #TPM_RC_VALUE Note: [1] The TPM_ALG_ID or TPM_ECC_CURVE is cast to a UINT32 [2] The TPM will return TPM_RC_VALUE if the handle does not reference the range for permanent handles. [3] TPM_CAP_AUTH_POLICIES was added in version 1.38. [4] TPM_CAP_ACT was added in version 1.59. [5] TPM_CAP_PUB_KEYS and TPM_CAP_SPDM_SESSION_INFO were added in version 184. .
    /// </summary>
    TPM_CAP_VENDOR_PROPERTY = 0x00000100
}