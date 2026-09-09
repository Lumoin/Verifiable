using System;

namespace Verifiable.Tpm.Spec.Constants;

/// <summary>
/// TPM_PUB_KEY constants (Table 31).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 31).
/// </para>
/// </remarks>
public enum TpmPubKeyConstants : uint
{
    /// <summary>
    /// Start of the property range for TPM SPDM authentication public keys
    /// </summary>
    TPM_PUB_KEY_TPM_SPDM_00 = 0x00000000,

    /// <summary>
    /// End of the property range for TPM SPDM authentication public keys
    /// </summary>
    TPM_PUB_KEY_TPM_SPDM_FF = 0x000000FF
}
