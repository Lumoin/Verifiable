using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Handles;

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
    /// TPM_HT_PCR range base (0x00).
    /// </summary>
    public const uint HR_PCR = (uint)TpmHt.TPM_HT_PCR;

    /// <summary>
    /// TPM_HT_HMAC_SESSION range base (0x02).
    /// </summary>
    public const uint HR_HMAC_SESSION = (uint)TpmHt.TPM_HT_HMAC_SESSION;

    /// <summary>
    /// TPM_HT_POLICY_SESSION range base (0x03).
    /// </summary>
    public const uint HR_POLICY_SESSION = (uint)TpmHt.TPM_HT_POLICY_SESSION;

    /// <summary>
    /// TPM_HT_TRANSIENT range base (0x80).
    /// </summary>
    public const uint HR_TRANSIENT = (uint)TpmHt.TPM_HT_TRANSIENT;

    /// <summary>
    /// TPM_HT_PERSISTENT range base (0x81).
    /// </summary>
    public const uint HR_PERSISTENT = (uint)TpmHt.TPM_HT_PERSISTENT;

    /// <summary>
    /// TPM_HT_NV_INDEX range base (0x01).
    /// </summary>
    public const uint HR_NV_INDEX = (uint)TpmHt.TPM_HT_NV_INDEX;

    /// <summary>
    /// TPM_HT_EXTERNAL_NV range base (0xA0).
    /// </summary>
    public const uint HR_EXTERNAL_NV = (uint)TpmHt.TPM_HT_EXTERNAL_NV;

    /// <summary>
    /// TPM_HT_PERMANENT_NV range base (0xA1).
    /// </summary>
    public const uint HR_PERMANENT_NV = (uint)TpmHt.TPM_HT_PERMANENT_NV;

    /// <summary>
    /// TPM_HT_PERMANENT range base (0x40).
    /// </summary>
    public const uint HR_PERMANENT = (uint)TpmHt.TPM_HT_PERMANENT;

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
    /// First values for external NV Index handle ranges.
    /// </summary>
    public const uint EXTERNAL_NV_FIRST = 0xA000_0000;

    /// <summary>
    /// Last values for external NV Index handle ranges.
    /// </summary>
    public const uint EXTERNAL_NV_LAST = 0xA0FF_FFFF;

    /// <summary>
    /// First values for permanent NV Index handle ranges.
    /// </summary>
    public const uint PERMANENT_NV_FIRST = 0xA100_0000;

    /// <summary>
    /// Last values for permanent NV Index handle ranges.
    /// </summary>
    public const uint PERMANENT_NV_LAST = 0xA1FF_FFFF;

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