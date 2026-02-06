using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Infrastructure.Spec.Handles;


/// <summary>
/// TPM 2.0 permanent and reserved hierarchy handles (TPM_RH).
/// </summary>
/// <remarks>
/// <para>
/// Purpose: Permanent handles identify well-known TPM resources such as hierarchies,
/// authorization values, and special pseudo-handles.
/// </para>
/// <para>
/// Retrieval: Many of these values appear in capability queries (e.g., handles returned from
/// <c>TPM2_GetCapability</c> with <c>capability == TPM_CAP_HANDLES</c>), and they are used directly
/// as input handles for numerous commands.
/// </para>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "Handles" / TPM_RH).
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "This follows the TPM 2.0 specification.")]
[SuppressMessage("Design", "CA1069:Enums values should not be duplicated", Justification = "This follows the TPM 2.0 specification.")]
public enum TpmRh: uint
{
    /// <summary>
    /// TPM_RH_FIRST (0x4000_0000): First permanent handle value (same as TPM_RH_SRK).
    /// </summary>
    TPM_RH_FIRST = 0x4000_0000,

    /// <summary>
    /// TPM_RH_SRK (0x4000_0000): Storage Root Key handle (reserved).
    /// </summary>
    TPM_RH_SRK = 0x4000_0000,

    /// <summary>
    /// TPM_RH_OWNER (0x4000_0001): Owner hierarchy.
    /// </summary>
    TPM_RH_OWNER = 0x4000_0001,

    /// <summary>
    /// TPM_RH_REVOKE (0x4000_0002): Reserved.
    /// </summary>
    TPM_RH_REVOKE = 0x4000_0002,

    /// <summary>
    /// TPM_RH_TRANSPORT (0x4000_0003): Reserved.
    /// </summary>
    TPM_RH_TRANSPORT = 0x4000_0003,

    /// <summary>
    /// TPM_RH_OPERATOR (0x4000_0004): Reserved.
    /// </summary>
    TPM_RH_OPERATOR = 0x4000_0004,

    /// <summary>
    /// TPM_RH_ADMIN (0x4000_0005): Reserved.
    /// </summary>
    TPM_RH_ADMIN = 0x4000_0005,

    /// <summary>
    /// TPM_RH_EK (0x4000_0006): Endorsement primary seed key handle (reserved).
    /// </summary>
    TPM_RH_EK = 0x4000_0006,

    /// <summary>
    /// TPM_RH_NULL (0x4000_0007): NULL hierarchy.
    /// </summary>
    TPM_RH_NULL = 0x4000_0007,

    /// <summary>
    /// TPM_RH_UNASSIGNED (0x4000_0008): Reserved.
    /// </summary>
    TPM_RH_UNASSIGNED = 0x4000_0008,

    /// <summary>
    /// TPM_RH_PW (0x4000_0009): Authorization session indicating password authorization.
    /// </summary>
    TPM_RH_PW = 0x4000_0009,

    /// <summary>
    /// TPM_RH_LOCKOUT (0x4000_000A): Lockout hierarchy.
    /// </summary>
    TPM_RH_LOCKOUT = 0x4000_000A,

    /// <summary>
    /// TPM_RH_ENDORSEMENT (0x4000_000B): Endorsement hierarchy.
    /// </summary>
    TPM_RH_ENDORSEMENT = 0x4000_000B,

    /// <summary>
    /// TPM_RH_PLATFORM (0x4000_000C): Platform hierarchy.
    /// </summary>
    TPM_RH_PLATFORM = 0x4000_000C,

    /// <summary>
    /// TPM_RH_PLATFORM_NV (0x4000_000D): Platform NV hierarchy.
    /// </summary>
    TPM_RH_PLATFORM_NV = 0x4000_000D,

    /// <summary>
    /// TPM_RH_AUTH_00 (0x4000_0100): Start of the authorization handle range.
    /// </summary>
    TPM_RH_AUTH_00 = 0x4000_0100,

    /// <summary>
    /// TPM_RH_AUTH_FF (0x4000_01FF): End of the authorization handle range.
    /// </summary>
    TPM_RH_AUTH_FF = 0x4000_01FF,

    /// <summary>
    /// TPM_RH_ACT_0 (0x4000_0110): ACT handle 0.
    /// </summary>
    TPM_RH_ACT_0 = 0x4000_0110,

    /// <summary>
    /// TPM_RH_ACT_F (0x4000_011F): ACT handle F.
    /// </summary>
    TPM_RH_ACT_F = 0x4000_011F,

    /// <summary>
    /// TPM_RH_LAST (0x4000_01FF): Last permanent handle value.
    /// </summary>
    TPM_RH_LAST = 0x4000_01FF,

    /// <summary>
    /// TPM_RH_SVN_OWNER_BASE (0x4001_0000): Base for SVN-limited Owner hierarchy.
    /// The low 2 bytes represent the minimum SVN value to which the hierarchy is limited.
    /// </summary>
    TPM_RH_SVN_OWNER_BASE = 0x4001_0000,

    /// <summary>
    /// TPM_RH_SVN_ENDORSEMENT_BASE (0x4002_0000): Base for SVN-limited Endorsement hierarchy.
    /// The low 2 bytes represent the minimum SVN value to which the hierarchy is limited.
    /// </summary>
    TPM_RH_SVN_ENDORSEMENT_BASE = 0x4002_0000,

    /// <summary>
    /// TPM_RH_SVN_PLATFORM_BASE (0x4003_0000): Base for SVN-limited Platform hierarchy.
    /// The low 2 bytes represent the minimum SVN value to which the hierarchy is limited.
    /// </summary>
    TPM_RH_SVN_PLATFORM_BASE = 0x4003_0000,

    /// <summary>
    /// TPM_RH_SVN_NULL_BASE (0x4004_0000): Base for SVN-limited NULL hierarchy.
    /// The low 2 bytes represent the minimum SVN value to which the hierarchy is limited.
    /// </summary>
    TPM_RH_SVN_NULL_BASE = 0x4004_0000,

    /// <summary>
    /// TPM_RH_RSVD_LAST (0x4004_FFFF): Top of the reserved handle area. This is set to allow
    /// <c>TPM2_GetCapability</c> to know where to stop. It may vary as implementations add to the reserved area.
    /// </summary>
    TPM_RH_RSVD_LAST = 0x4004_FFFF,
}
