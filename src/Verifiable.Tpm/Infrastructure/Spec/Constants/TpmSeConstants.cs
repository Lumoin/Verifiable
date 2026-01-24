namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// TPM_SE constants (Table 25).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 25).
/// </para>
/// </remarks>
public enum TpmSeConstants : byte
{
    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_SE_HMAC = 0x00,

    /// <summary>
    /// (no comment text in extracted table)
    /// </summary>
    TPM_SE_POLICY = 0x01,

    /// <summary>
    /// the policy session is being used to compute the policyHash and not for command authorization This setting modifies some policy commands and prevents session from being used to authorize a command. #TPM_RC_VALUE response code when incorrect value is used
    /// </summary>
    TPM_SE_TRIAL = 0x03
}