using System;
using System.Buffers.Binary;
using System.Text;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Shared conversion utilities for TPM value interpretation.
/// </summary>
/// <remarks>
/// <para>
/// Provides formatting and interpretation methods for common TPM value types
/// such as handles, ASCII-encoded strings, versions, and sizes.
/// </para>
/// </remarks>
public static class TpmValueConversions
{
    /// <summary>
    /// Converts a 32-bit value to a 4-character ASCII string.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Many TPM properties encode 4-character ASCII strings in a UINT32 using
    /// big-endian byte order. This includes manufacturer IDs, vendor strings,
    /// and family indicators.
    /// </para>
    /// <para>
    /// Example: 0x494E5443 → "INTC" (Intel).
    /// </para>
    /// </remarks>
    /// <param name="value">The 32-bit value (big-endian encoded ASCII).</param>
    /// <returns>The ASCII string, or hex representation if non-printable characters are present.</returns>
    public static string ToAscii4(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);

        foreach(byte b in bytes)
        {
            if(b != 0 && (b < 0x20 || b > 0x7E))
            {
                return $"0x{value:X8}";
            }
        }

        return Encoding.ASCII.GetString(bytes).TrimEnd('\0');
    }

    /// <summary>
    /// Gets a description for a TPM handle using spec-defined types and ranges.
    /// </summary>
    /// <remarks>
    /// <para>
    /// TPM handles encode the handle type in the most-significant octet (MSO)
    /// and a 24-bit index in the remaining bits. This method uses <see cref="TpmHandleRanges"/>
    /// to decode the handle type and format an appropriate description.
    /// </para>
    /// <para>
    /// Specification reference: TPM 2.0 Library Part 2, section 7.4.
    /// </para>
    /// </remarks>
    /// <param name="handle">The TPM handle.</param>
    /// <returns>A human-readable description of the handle.</returns>
    public static string GetHandleDescription(uint handle)
    {
        TpmHt handleType = TpmHandleRanges.GetHandleType(handle);
        uint index = TpmHandleRanges.GetHandleIndex(handle);

        return handleType switch
        {
            TpmHt.TPM_HT_PCR => $"PCR[{index}]",
            TpmHt.TPM_HT_NV_INDEX => $"NV_INDEX[0x{handle:X8}]",
            TpmHt.TPM_HT_HMAC_SESSION => $"HMAC_SESSION[0x{index:X6}]",
            TpmHt.TPM_HT_POLICY_SESSION => $"POLICY_SESSION[0x{index:X6}]",
            TpmHt.TPM_HT_PERMANENT => GetPermanentHandleName(handle),
            TpmHt.TPM_HT_TRANSIENT => $"TRANSIENT[0x{index:X6}]",
            TpmHt.TPM_HT_PERSISTENT => $"PERSISTENT[0x{index:X6}]",
            TpmHt.TPM_HT_AC => $"AC[0x{index:X6}]",
            TpmHt.TPM_HT_EXTERNAL_NV => $"EXTERNAL_NV[0x{index:X6}]",
            TpmHt.TPM_HT_PERMANENT_NV => $"PERMANENT_NV[0x{index:X6}]",
            _ => $"0x{handle:X8}"
        };
    }

    private static string GetPermanentHandleName(uint handle)
    {
        return handle switch
        {
            (uint)TpmRh.TPM_RH_SRK => "TPM_RH_SRK",
            (uint)TpmRh.TPM_RH_OWNER => "TPM_RH_OWNER",
            (uint)TpmRh.TPM_RH_REVOKE => "TPM_RH_REVOKE",
            (uint)TpmRh.TPM_RH_TRANSPORT => "TPM_RH_TRANSPORT",
            (uint)TpmRh.TPM_RH_OPERATOR => "TPM_RH_OPERATOR",
            (uint)TpmRh.TPM_RH_ADMIN => "TPM_RH_ADMIN",
            (uint)TpmRh.TPM_RH_EK => "TPM_RH_EK",
            (uint)TpmRh.TPM_RH_NULL => "TPM_RH_NULL",
            (uint)TpmRh.TPM_RH_UNASSIGNED => "TPM_RH_UNASSIGNED",
            (uint)TpmRh.TPM_RH_PW => "TPM_RH_PW",
            (uint)TpmRh.TPM_RH_LOCKOUT => "TPM_RH_LOCKOUT",
            (uint)TpmRh.TPM_RH_ENDORSEMENT => "TPM_RH_ENDORSEMENT",
            (uint)TpmRh.TPM_RH_PLATFORM => "TPM_RH_PLATFORM",
            (uint)TpmRh.TPM_RH_PLATFORM_NV => "TPM_RH_PLATFORM_NV",
            (uint)TpmRh.TPM_RH_AUTH_00 => "TPM_RH_AUTH_00",
            (uint)TpmRh.TPM_RH_AUTH_FF => "TPM_RH_AUTH_FF",
            (uint)TpmRh.TPM_RH_SVN_OWNER_BASE => "TPM_RH_SVN_OWNER_BASE",
            (uint)TpmRh.TPM_RH_SVN_ENDORSEMENT_BASE => "TPM_RH_SVN_ENDORSEMENT_BASE",
            (uint)TpmRh.TPM_RH_SVN_PLATFORM_BASE => "TPM_RH_SVN_PLATFORM_BASE",
            (uint)TpmRh.TPM_RH_SVN_NULL_BASE => "TPM_RH_SVN_NULL_BASE",
            //ACT handles (TPM_RH_ACT_0 through TPM_RH_ACT_F).
            >= (uint)TpmRh.TPM_RH_ACT_0 and <= (uint)TpmRh.TPM_RH_ACT_F =>
                $"TPM_RH_ACT_{handle - (uint)TpmRh.TPM_RH_ACT_0:X}",
            _ => $"TPM_RH_0x{handle:X8}"
        };
    }

    /// <summary>
    /// Formats a version from high/low 16-bit parts.
    /// </summary>
    /// <remarks>
    /// <para>
    /// TPM firmware versions are typically encoded with the major version in the
    /// high 16 bits and the minor version in the low 16 bits.
    /// </para>
    /// <para>
    /// Example: 0x00010002 → "1.2".
    /// </para>
    /// </remarks>
    /// <param name="value">The 32-bit version value.</param>
    /// <returns>A formatted version string (e.g., "7.85").</returns>
    public static string ToVersion(uint value)
    {
        uint major = value >> 16;
        uint minor = value & 0xFFFF;
        return $"{major}.{minor}";
    }

    /// <summary>
    /// Converts a UINT32 to a date string (year.dayOfYear).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used for properties like TPM_PT_YEAR and TPM_PT_DAY_OF_YEAR
    /// combined into a single value.
    /// </para>
    /// </remarks>
    /// <param name="year">The year value.</param>
    /// <param name="dayOfYear">The day of year value (1-366).</param>
    /// <returns>A date string in "year.dayOfYear" format.</returns>
    public static string ToDate(uint year, uint dayOfYear)
    {
        return $"{year}.{dayOfYear:D3}";
    }

    /// <summary>
    /// Formats a byte count with appropriate unit.
    /// </summary>
    /// <remarks>
    /// Used for properties like TPM_PT_MEMORY, TPM_PT_INPUT_BUFFER, etc.
    /// </remarks>
    /// <param name="bytes">The byte count.</param>
    /// <returns>A formatted size string (e.g., "4 KB", "1024 bytes").</returns>
    public static string ToByteSize(uint bytes)
    {
        return bytes switch
        {
            >= 1024 * 1024 => $"{bytes / (1024 * 1024)} MB",
            >= 1024 => $"{bytes / 1024} KB",
            _ => $"{bytes} bytes"
        };
    }

    /// <summary>
    /// Formats a count with singular/plural unit.
    /// </summary>
    /// <param name="count">The count value.</param>
    /// <param name="singular">The unit name (singular form).</param>
    /// <param name="plural">The plural form. If null, appends "s" to singular.</param>
    /// <returns>A formatted count string (e.g., "1 handle", "3 sessions").</returns>
    public static string ToCount(uint count, string singular, string? plural = null)
    {
        plural ??= singular + "s";
        return count == 1 ? $"1 {singular}" : $"{count} {plural}";
    }

    /// <summary>
    /// Converts bytes to hex with optional truncation for display purposes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Used primarily for <see cref="System.Diagnostics.DebuggerDisplayAttribute"/> where
    /// showing the full digest would be too verbose.
    /// </para>
    /// </remarks>
    /// <param name="bytes">The bytes to convert.</param>
    /// <param name="maxBytes">Maximum bytes to show before truncating.</param>
    /// <returns>Hex string, truncated with "..." and byte count if necessary.</returns>
    public static string ToHexPreview(ReadOnlySpan<byte> bytes, int maxBytes = 8)
    {
        if(bytes.IsEmpty)
        {
            return "(empty)";
        }

        if(bytes.Length <= maxBytes)
        {
            return Convert.ToHexString(bytes);
        }

        return Convert.ToHexString(bytes[..maxBytes]) + $"... ({bytes.Length} bytes)";
    }
}