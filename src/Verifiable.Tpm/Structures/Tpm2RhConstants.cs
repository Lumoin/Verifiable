namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM 2.0 reserved handles (TPM_RH) for permanent entities.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 7.6 - TPM_RH (Permanent Handles).
/// </para>
/// </remarks>
public enum Tpm2RhConstants: uint
{
    /// <summary>
    /// TPM_RH_FIRST: First reserved handle value.
    /// </summary>
    TPM_RH_FIRST = 0x40000000,

    /// <summary>
    /// TPM_RH_SRK: Storage Root Key handle. Not used in TPM 2.0.
    /// </summary>
    TPM_RH_SRK = 0x40000000,

    /// <summary>
    /// TPM_RH_OWNER: Storage hierarchy authorization handle.
    /// </summary>
    TPM_RH_OWNER = 0x40000001,

    /// <summary>
    /// TPM_RH_REVOKE: Revoke handle. Not used in TPM 2.0.
    /// </summary>
    TPM_RH_REVOKE = 0x40000002,

    /// <summary>
    /// TPM_RH_TRANSPORT: Transport handle. Not used in TPM 2.0.
    /// </summary>
    TPM_RH_TRANSPORT = 0x40000003,

    /// <summary>
    /// TPM_RH_OPERATOR: Operator hierarchy handle.
    /// </summary>
    TPM_RH_OPERATOR = 0x40000004,

    /// <summary>
    /// TPM_RH_ADMIN: Admin handle. Not used in TPM 2.0.
    /// </summary>
    TPM_RH_ADMIN = 0x40000005,

    /// <summary>
    /// TPM_RH_EK: Endorsement Key handle. Not used in TPM 2.0.
    /// </summary>
    TPM_RH_EK = 0x40000006,

    /// <summary>
    /// TPM_RH_NULL: Null hierarchy handle. Used when hierarchy is not applicable.
    /// </summary>
    TPM_RH_NULL = 0x40000007,

    /// <summary>
    /// TPM_RH_UNASSIGNED: Unassigned handle value.
    /// </summary>
    TPM_RH_UNASSIGNED = 0x40000008,

    /// <summary>
    /// TPM_RS_PW: Password authorization session.
    /// </summary>
    TPM_RS_PW = 0x40000009,

    /// <summary>
    /// TPM_RH_LOCKOUT: Lockout authorization handle.
    /// </summary>
    TPM_RH_LOCKOUT = 0x4000000A,

    /// <summary>
    /// TPM_RH_ENDORSEMENT: Endorsement hierarchy authorization handle.
    /// </summary>
    TPM_RH_ENDORSEMENT = 0x4000000B,

    /// <summary>
    /// TPM_RH_PLATFORM: Platform hierarchy authorization handle.
    /// </summary>
    TPM_RH_PLATFORM = 0x4000000C,

    /// <summary>
    /// TPM_RH_PLATFORM_NV: Platform NV authorization handle.
    /// </summary>
    TPM_RH_PLATFORM_NV = 0x4000000D,

    /// <summary>
    /// TPM_RH_AUTH_00: First authorization handle for TPM2_PolicyAuthorize.
    /// </summary>
    TPM_RH_AUTH_00 = 0x40000010,

    /// <summary>
    /// TPM_RH_AUTH_FF: Last authorization handle for TPM2_PolicyAuthorize.
    /// </summary>
    TPM_RH_AUTH_FF = 0x4000010F,

    /// <summary>
    /// TPM_RH_ACT_0: Authenticated Countdown Timer 0 handle.
    /// </summary>
    TPM_RH_ACT_0 = 0x40000110,

    /// <summary>
    /// TPM_RH_ACT_F: Authenticated Countdown Timer F handle.
    /// </summary>
    TPM_RH_ACT_F = 0x4000011F,

    /// <summary>
    /// TPM_RH_LAST: Last reserved handle value.
    /// </summary>
    TPM_RH_LAST = 0x4000011F
}