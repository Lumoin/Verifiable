namespace Verifiable.Tpm.Infrastructure.Spec.Handles;


/// <summary>
/// TPM_HC handle construction constants and handle-range helpers.
/// </summary>
/// <remarks>
/// <para>
/// Purpose: TPM handles are 32-bit values where the upper byte identifies the handle type (HR),
/// and the lower 24 bits hold the handle's variable part (index).
/// This table defines masks, shifts, and the base values for each handle range.
/// </para>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification
/// </see>
/// (Part 2: Structures, section "TPM_HC", Table 37).
/// </para>
/// <para>
/// Notes:
/// Some range limits are defined in the spec using implementation-dependent symbols
/// (e.g., <c>IMPLEMENTATION_PCR</c>, <c>MAX_ACTIVE_SESSIONS</c>, <c>MAX_LOADED_OBJECTS</c>).
/// Those are provided here as helper methods rather than compile-time constants.
/// </para>
/// </remarks>
public static class TpmHcConstants
{
    /// <summary>
    /// HR_HANDLE_MASK (0x00FFFFFF): mask off the HR (upper byte), leaving the variable part (low 24 bits).
    /// </summary>
    public const uint HR_HANDLE_MASK = 0x00FF_FFFF;

    /// <summary>
    /// HR_RANGE_MASK (0xFF000000): mask off the variable part, leaving the HR (upper byte).
    /// </summary>
    public const uint HR_RANGE_MASK = 0xFF00_0000;

    /// <summary>
    /// HR_SHIFT (24): shift count for the HR (upper byte).
    /// </summary>
    public const int HR_SHIFT = 24;

    /// <summary>
    /// HR_PCR: base for PCR handles (<c>TPM_HT_PCR &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_PCR = ((uint)TpmHt.TPM_HT_PCR) << HR_SHIFT;

    /// <summary>
    /// HR_HMAC_SESSION: base for HMAC session handles (<c>TPM_HT_HMAC_SESSION &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_HMAC_SESSION = ((uint)TpmHt.TPM_HT_HMAC_SESSION) << HR_SHIFT;

    /// <summary>
    /// HR_POLICY_SESSION: base for policy session handles (<c>TPM_HT_POLICY_SESSION &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_POLICY_SESSION = ((uint)TpmHt.TPM_HT_POLICY_SESSION) << HR_SHIFT;

    /// <summary>
    /// HR_TRANSIENT: base for transient object handles (<c>TPM_HT_TRANSIENT &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_TRANSIENT = ((uint)TpmHt.TPM_HT_TRANSIENT) << HR_SHIFT;

    /// <summary>
    /// HR_PERSISTENT: base for persistent object handles (<c>TPM_HT_PERSISTENT &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_PERSISTENT = ((uint)TpmHt.TPM_HT_PERSISTENT) << HR_SHIFT;

    /// <summary>
    /// HR_NV_INDEX: base for NV Index handles (<c>TPM_HT_NV_INDEX &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_NV_INDEX = ((uint)TpmHt.TPM_HT_NV_INDEX) << HR_SHIFT;

    /// <summary>
    /// HR_EXTERNAL_NV: base for external NV Index handles (<c>TPM_HT_EXTERNAL_NV &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_EXTERNAL_NV = ((uint)TpmHt.TPM_HT_EXTERNAL_NV) << HR_SHIFT;

    /// <summary>
    /// HR_PERMANENT_NV: base for permanent NV Index handles (<c>TPM_HT_PERMANENT_NV &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_PERMANENT_NV = ((uint)TpmHt.TPM_HT_PERMANENT_NV) << HR_SHIFT;

    /// <summary>
    /// HR_PERMANENT: base for permanent handles (<c>TPM_HT_PERMANENT &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_PERMANENT = ((uint)TpmHt.TPM_HT_PERMANENT) << HR_SHIFT;

    /// <summary>
    /// PCR_FIRST: first PCR (<c>HR_PCR + 0</c>).
    /// </summary>
    public const uint PCR_FIRST = HR_PCR + 0;

    /// <summary>
    /// Computes PCR_LAST: <c>PCR_FIRST + IMPLEMENTATION_PCR - 1</c>.
    /// </summary>
    public static uint GetPcrLast(uint implementationPcr)
    {
        return PCR_FIRST + implementationPcr - 1;
    }

    /// <summary>
    /// HMAC_SESSION_FIRST: first HMAC session (<c>HR_HMAC_SESSION + 0</c>).
    /// </summary>
    public const uint HMAC_SESSION_FIRST = HR_HMAC_SESSION + 0;

    /// <summary>
    /// Computes HMAC_SESSION_LAST: <c>HMAC_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1</c>.
    /// </summary>
    public static uint GetHmacSessionLast(uint maxActiveSessions)
    {
        return HMAC_SESSION_FIRST + maxActiveSessions - 1;
    }

    /// <summary>
    /// LOADED_SESSION_FIRST: used in GetCapability (same value as <see cref="HMAC_SESSION_FIRST"/>).
    /// </summary>
    public const uint LOADED_SESSION_FIRST = HMAC_SESSION_FIRST;

    /// <summary>
    /// Computes LOADED_SESSION_LAST: used in GetCapability (same formula as HMAC_SESSION_LAST).
    /// </summary>
    public static uint GetLoadedSessionLast(uint maxActiveSessions)
    {
        return GetHmacSessionLast(maxActiveSessions);
    }

    /// <summary>
    /// POLICY_SESSION_FIRST: first policy session (<c>HR_POLICY_SESSION + 0</c>).
    /// </summary>
    public const uint POLICY_SESSION_FIRST = HR_POLICY_SESSION + 0;

    /// <summary>
    /// Computes POLICY_SESSION_LAST: <c>POLICY_SESSION_FIRST + MAX_ACTIVE_SESSIONS - 1</c>.
    /// </summary>
    public static uint GetPolicySessionLast(uint maxActiveSessions)
    {
        return POLICY_SESSION_FIRST + maxActiveSessions - 1;
    }

    /// <summary>
    /// ACTIVE_SESSION_FIRST: used in GetCapability (same value as <see cref="POLICY_SESSION_FIRST"/>).
    /// </summary>
    public const uint ACTIVE_SESSION_FIRST = POLICY_SESSION_FIRST;

    /// <summary>
    /// Computes ACTIVE_SESSION_LAST: used in GetCapability (same formula as POLICY_SESSION_LAST).
    /// </summary>
    public static uint GetActiveSessionLast(uint maxActiveSessions)
    {
        return GetPolicySessionLast(maxActiveSessions);
    }

    /// <summary>
    /// TRANSIENT_FIRST: first transient object (<c>HR_TRANSIENT + 0</c>).
    /// </summary>
    public const uint TRANSIENT_FIRST = HR_TRANSIENT + 0;

    /// <summary>
    /// Computes TRANSIENT_LAST: <c>TRANSIENT_FIRST + MAX_LOADED_OBJECTS - 1</c>.
    /// </summary>
    public static uint GetTransientLast(uint maxLoadedObjects)
    {
        return TRANSIENT_FIRST + maxLoadedObjects - 1;
    }

    /// <summary>
    /// PERSISTENT_FIRST: first persistent object (<c>HR_PERSISTENT + 0</c>).
    /// </summary>
    public const uint PERSISTENT_FIRST = HR_PERSISTENT + 0;

    /// <summary>
    /// PERSISTENT_LAST: last persistent object (<c>PERSISTENT_FIRST + 0x00FFFFFF</c>).
    /// </summary>
    public const uint PERSISTENT_LAST = PERSISTENT_FIRST + 0x00FF_FFFF;

    /// <summary>
    /// PLATFORM_PERSISTENT: first platform persistent object (<c>PERSISTENT_FIRST + 0x00800000</c>).
    /// </summary>
    public const uint PLATFORM_PERSISTENT = PERSISTENT_FIRST + 0x0080_0000;

    /// <summary>
    /// NV_INDEX_FIRST: first allowed NV Index with 32-bit attributes (<c>HR_NV_INDEX + 0</c>).
    /// </summary>
    public const uint NV_INDEX_FIRST = HR_NV_INDEX + 0;

    /// <summary>
    /// NV_INDEX_LAST: last allowed NV Index with 32-bit attributes (<c>NV_INDEX_FIRST + 0x00FFFFFF</c>).
    /// </summary>
    public const uint NV_INDEX_LAST = NV_INDEX_FIRST + 0x00FF_FFFF;

    /// <summary>
    /// EXTERNAL_NV_FIRST: first external NV Index (<c>HR_EXTERNAL_NV + 0</c>).
    /// </summary>
    public const uint EXTERNAL_NV_FIRST = HR_EXTERNAL_NV + 0;

    /// <summary>
    /// EXTERNAL_NV_LAST: last external NV Index (<c>EXTERNAL_NV_FIRST + 0x00FFFFFF</c>).
    /// </summary>
    public const uint EXTERNAL_NV_LAST = EXTERNAL_NV_FIRST + 0x00FF_FFFF;

    /// <summary>
    /// PERMANENT_NV_FIRST: first permanent NV Index (<c>HR_PERMANENT_NV + 0</c>).
    /// </summary>
    public const uint PERMANENT_NV_FIRST = HR_PERMANENT_NV + 0;

    /// <summary>
    /// PERMANENT_NV_LAST: last permanent NV Index (<c>PERMANENT_NV_FIRST + 0x00FFFFFF</c>).
    /// </summary>
    public const uint PERMANENT_NV_LAST = PERMANENT_NV_FIRST + 0x00FF_FFFF;

    /// <summary>
    /// PERMANENT_FIRST: first permanent handle (same as <c>TPM_RH_FIRST</c>).
    /// </summary>
    public const uint PERMANENT_FIRST = (uint)TpmRh.TPM_RH_FIRST;

    /// <summary>
    /// PERMANENT_LAST: last permanent handle (same as <c>TPM_RH_LAST</c>).
    /// </summary>
    public const uint PERMANENT_LAST = (uint)TpmRh.TPM_RH_LAST;

    /// <summary>
    /// SVN_OWNER_FIRST: <c>TPM_RH_SVN_OWNER_BASE + 0x0000</c>.
    /// </summary>
    public const uint SVN_OWNER_FIRST = (uint)TpmRh.TPM_RH_SVN_OWNER_BASE + 0x0000;

    /// <summary>
    /// SVN_OWNER_LAST: <c>TPM_RH_SVN_OWNER_BASE + 0xFFFF</c>.
    /// </summary>
    public const uint SVN_OWNER_LAST = (uint)TpmRh.TPM_RH_SVN_OWNER_BASE + 0xFFFF;

    /// <summary>
    /// SVN_ENDORSEMENT_FIRST: <c>TPM_RH_SVN_ENDORSEMENT_BASE + 0x0000</c>.
    /// </summary>
    public const uint SVN_ENDORSEMENT_FIRST = (uint)TpmRh.TPM_RH_SVN_ENDORSEMENT_BASE + 0x0000;

    /// <summary>
    /// SVN_ENDORSEMENT_LAST: <c>TPM_RH_SVN_ENDORSEMENT_BASE + 0xFFFF</c>.
    /// </summary>
    public const uint SVN_ENDORSEMENT_LAST = (uint)TpmRh.TPM_RH_SVN_ENDORSEMENT_BASE + 0xFFFF;

    /// <summary>
    /// SVN_PLATFORM_FIRST: <c>TPM_RH_SVN_PLATFORM_BASE + 0x0000</c>.
    /// </summary>
    public const uint SVN_PLATFORM_FIRST = (uint)TpmRh.TPM_RH_SVN_PLATFORM_BASE + 0x0000;

    /// <summary>
    /// SVN_PLATFORM_LAST: <c>TPM_RH_SVN_PLATFORM_BASE + 0xFFFF</c>.
    /// </summary>
    public const uint SVN_PLATFORM_LAST = (uint)TpmRh.TPM_RH_SVN_PLATFORM_BASE + 0xFFFF;

    /// <summary>
    /// SVN_NULL_FIRST: <c>TPM_RH_SVN_NULL_BASE + 0x0000</c>.
    /// </summary>
    public const uint SVN_NULL_FIRST = (uint)TpmRh.TPM_RH_SVN_NULL_BASE + 0x0000;

    /// <summary>
    /// SVN_NULL_LAST: <c>TPM_RH_SVN_NULL_BASE + 0xFFFF</c>.
    /// </summary>
    public const uint SVN_NULL_LAST = (uint)TpmRh.TPM_RH_SVN_NULL_BASE + 0xFFFF;

    /// <summary>
    /// HR_NV_AC: AC aliased NV Index base (<c>(TPM_HT_NV_INDEX &lt;&lt; HR_SHIFT) + 0xD00000</c>).
    /// </summary>
    public const uint HR_NV_AC = (((uint)TpmHt.TPM_HT_NV_INDEX) << HR_SHIFT) + 0x00D0_0000;

    /// <summary>
    /// NV_AC_FIRST: first NV Index aliased to Attached Component (<c>HR_NV_AC + 0</c>).
    /// </summary>
    public const uint NV_AC_FIRST = HR_NV_AC + 0;

    /// <summary>
    /// NV_AC_LAST: last NV Index aliased to Attached Component (<c>HR_NV_AC + 0x0000FFFF</c>).
    /// </summary>
    public const uint NV_AC_LAST = HR_NV_AC + 0x0000_FFFF;

    /// <summary>
    /// HR_AC: Attached Component handle base (<c>TPM_HT_AC &lt;&lt; HR_SHIFT</c>).
    /// </summary>
    public const uint HR_AC = ((uint)TpmHt.TPM_HT_AC) << HR_SHIFT;

    /// <summary>
    /// AC_FIRST: first Attached Component (<c>HR_AC + 0</c>).
    /// </summary>
    public const uint AC_FIRST = HR_AC + 0;

    /// <summary>
    /// AC_LAST: last Attached Component (<c>HR_AC + 0x0000FF</c>).
    /// </summary>
    public const uint AC_LAST = HR_AC + 0x0000_00FF;

    /// <summary>
    /// Extracts the handle type (upper byte / HR) from a TPM handle.
    /// </summary>
    public static TpmHt GetHandleType(uint handle)
    {
        return (TpmHt)((handle & HR_RANGE_MASK) >> HR_SHIFT);
    }

    /// <summary>
    /// Extracts the variable part (low 24 bits) from a TPM handle.
    /// </summary>
    public static uint GetHandleIndex(uint handle)
    {
        return handle & HR_HANDLE_MASK;
    }

    /// <summary>
    /// Constructs a handle from a handle type and index (low 24 bits).
    /// </summary>
    public static uint MakeHandle(TpmHt handleType, uint index)
    {
        return (((uint)handleType) << HR_SHIFT) | (index & HR_HANDLE_MASK);
    }
}
