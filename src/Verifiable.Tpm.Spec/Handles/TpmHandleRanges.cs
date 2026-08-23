using System;

namespace Verifiable.Tpm.Spec.Handles;

/// <summary>
/// Handle encoding helpers and common handle ranges.
/// </summary>
/// <remarks>
/// <para>
/// A TPM handle is a 32-bit value. The most-significant octet (MSO) encodes the handle type (<see cref="TpmHt"/>),
/// and the least-significant 24 bits encode an index within that type.
/// </para>
/// <para>
/// This class provides convenient constants and helpers for composing and decomposing handles.
/// </para>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "Handles").

/// </para>
/// </remarks>
public static class TpmHandleRanges
{
    /// <summary>
    /// HR_SHIFT (24): Number of bits to shift to extract the handle type (MSO).
    /// </summary>
    public const int HR_SHIFT = 24;

    /// <summary>
    /// HR_HANDLE_MASK (0x00FF_FFFF): Mask for the low 24-bit handle index.
    /// </summary>
    public const uint HR_HANDLE_MASK = 0x00FF_FFFF;

    /// <summary>
    /// HR_RANGE_MASK (0xFF00_0000): Mask for the handle type (MSO).
    /// </summary>
    public const uint HR_RANGE_MASK = 0xFF00_0000;

    /// <summary>
    /// First value of the PCR range (<c>PCR_FIRST</c>). PCR 0 is architecturally defined to have a handle value
    /// of zero, so this equals zero (Part 2, clause 7.5, Table 37: <c>HR_PCR = TPM_HT_PCR « HR_SHIFT</c>).
    /// </summary>
    /// <remarks>
    /// Part 2, clause 7.5, Table 37 defines <c>PCR_LAST</c> as <c>PCR_FIRST + IMPLEMENTATION_PCR - 1</c>, an
    /// implementation-dependent bound (see <see cref="TpmHcConstants.GetPcrLast"/> for that formula). This pair
    /// instead spans the type's full 24-bit index space, mirroring how <see cref="TRANSIENT_FIRST"/> and
    /// <see cref="TRANSIENT_LAST"/> already model their range here — for classifying a handle's interface type
    /// (<see cref="TpmiDhPcr"/>, <see cref="TpmiDhEntity"/>), not for an implementation's live
    /// PCR count.
    /// </remarks>
    public const uint PCR_FIRST = 0x0000_0000;

    /// <summary>
    /// Last value of the PCR range this class models (the full 24-bit index space under <see cref="TpmHcConstants.HR_PCR"/>);
    /// see the <see cref="PCR_FIRST"/> remarks for how this differs from the spec's implementation-dependent
    /// <c>PCR_LAST</c>.
    /// </summary>
    public const uint PCR_LAST = 0x00FF_FFFF;

    /// <summary>
    /// First value of the HMAC session range (<c>HMAC_SESSION_FIRST</c>).
    /// </summary>
    /// <remarks>
    /// Part 2, clause 7.5, Table 37 defines <c>HMAC_SESSION_LAST</c> as <c>HMAC_SESSION_FIRST +
    /// MAX_ACTIVE_SESSIONS - 1</c>, an implementation-dependent bound (see
    /// <see cref="TpmHcConstants.GetHmacSessionLast"/> for that formula). This pair instead spans the type's
    /// full 24-bit index space, mirroring <see cref="TRANSIENT_FIRST"/>/<see cref="TRANSIENT_LAST"/> — for
    /// classifying a handle's interface type (<see cref="TpmiShHmac"/>, <see cref="TpmiDhContext"/>),
    /// not for an implementation's live session count.
    /// </remarks>
    public const uint HMAC_SESSION_FIRST = 0x0200_0000;

    /// <summary>
    /// Last value of the HMAC session range this class models (the full 24-bit index space under
    /// <see cref="TpmHcConstants.HR_HMAC_SESSION"/>); see the <see cref="HMAC_SESSION_FIRST"/> remarks.
    /// </summary>
    public const uint HMAC_SESSION_LAST = 0x02FF_FFFF;

    /// <summary>
    /// First value of the policy session range (<c>POLICY_SESSION_FIRST</c>).
    /// </summary>
    /// <remarks>
    /// Part 2, clause 7.5, Table 37 defines <c>POLICY_SESSION_LAST</c> as <c>POLICY_SESSION_FIRST +
    /// MAX_ACTIVE_SESSIONS - 1</c>, an implementation-dependent bound (see
    /// <see cref="TpmHcConstants.GetPolicySessionLast"/> for that formula). This pair instead spans the type's
    /// full 24-bit index space, mirroring <see cref="TRANSIENT_FIRST"/>/<see cref="TRANSIENT_LAST"/> — for
    /// classifying a handle's interface type (<see cref="TpmiShPolicy"/>, <see cref="TpmiDhContext"/>),
    /// not for an implementation's live session count.
    /// </remarks>
    public const uint POLICY_SESSION_FIRST = 0x0300_0000;

    /// <summary>
    /// Last value of the policy session range this class models (the full 24-bit index space under
    /// <see cref="TpmHcConstants.HR_POLICY_SESSION"/>); see the <see cref="POLICY_SESSION_FIRST"/> remarks.
    /// </summary>
    public const uint POLICY_SESSION_LAST = 0x03FF_FFFF;

    /// <summary>
    /// First values for key handle ranges.
    /// </summary>
    public const uint TRANSIENT_FIRST = 0x8000_0000;

    /// <summary>
    /// Last values for key handle ranges.
    /// </summary>
    public const uint TRANSIENT_LAST = 0x80FF_FFFF;

    /// <summary>
    /// First values for persistent object handle ranges.
    /// </summary>
    public const uint PERSISTENT_FIRST = 0x8100_0000;

    /// <summary>
    /// Last values for persistent object handle ranges.
    /// </summary>
    public const uint PERSISTENT_LAST = 0x81FF_FFFF;

    /// <summary>
    /// First and last values for NV Index handle ranges.
    /// </summary>
    public const uint NV_INDEX_FIRST = 0x0100_0000;

    /// <summary>
    /// Last values for NV Index handle ranges.
    /// </summary>
    public const uint NV_INDEX_LAST = 0x01FF_FFFF;

    /// <summary>
    /// First value of the external NV Index handle range (Part 2, clause 7.2, Table 35: <c>TPM_HT_EXTERNAL_NV = 0x11</c>; clause 7.5, Table 37).
    /// </summary>
    public const uint EXTERNAL_NV_FIRST = 0x1100_0000;

    /// <summary>
    /// Last value of the external NV Index handle range.
    /// </summary>
    public const uint EXTERNAL_NV_LAST = 0x11FF_FFFF;

    /// <summary>
    /// First value of the permanent NV Index handle range (Part 2, clause 7.2, Table 35: <c>TPM_HT_PERMANENT_NV = 0x12</c>; clause 7.5, Table 37).
    /// </summary>
    public const uint PERMANENT_NV_FIRST = 0x1200_0000;

    /// <summary>
    /// Last value of the permanent NV Index handle range.
    /// </summary>
    public const uint PERMANENT_NV_LAST = 0x12FF_FFFF;

    /// <summary>
    /// Extracts the handle type (MSO) from a 32-bit TPM handle.
    /// </summary>
    public static TpmHt GetHandleType(uint handle)
    {
        return (TpmHt)((handle & HR_RANGE_MASK) >> HR_SHIFT);
    }

    /// <summary>
    /// Extracts the low 24-bit index from a 32-bit TPM handle.
    /// </summary>
    public static uint GetHandleIndex(uint handle)
    {
        return handle & HR_HANDLE_MASK;
    }

    /// <summary>
    /// Constructs a handle from a handle type and a 24-bit index.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if <paramref name="index"/> exceeds 24 bits.</exception>
    public static uint MakeHandle(TpmHt type, uint index)
    {
        if((index & ~HR_HANDLE_MASK) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(index), "Handle index must fit in 24 bits.");
        }

        return ((uint)type << HR_SHIFT) | index;
    }
}
