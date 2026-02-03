using System;

namespace Verifiable.Tpm;

/// <summary>
/// Information about the TPM that produced a recording.
/// </summary>
/// <remarks>
/// <para>
/// This record captures metadata about a TPM session for diagnostic and replay purposes.
/// It is typically created via <see cref="TpmDeviceExtensions.GetSessionInfo"/> and
/// stored alongside recorded exchanges in a <see cref="TpmRecording"/>.
/// </para>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see> for TPM property details.
/// </para>
/// </remarks>
/// <param name="Manufacturer">TPM manufacturer identifier (4-character ASCII string).</param>
/// <param name="FirmwareVersion">TPM firmware version string.</param>
/// <param name="Platform">Platform on which the recording was made.</param>
/// <param name="RecordedAt">Timestamp when recording started.</param>
/// <seealso cref="TpmRecording"/>
/// <seealso cref="TpmDeviceExtensions.GetSessionInfo"/>
public sealed record TpmSessionInfo(
    string? Manufacturer,
    string? FirmwareVersion,
    TpmPlatform Platform,
    DateTimeOffset RecordedAt)
{
    /// <summary>
    /// Creates a new session info with the current time from the specified provider.
    /// </summary>
    /// <param name="manufacturer">TPM manufacturer identifier.</param>
    /// <param name="firmwareVersion">TPM firmware version string.</param>
    /// <param name="platform">Platform on which the recording was made.</param>
    /// <param name="timeProvider">Time provider for obtaining the current timestamp.</param>
    /// <returns>A new session info instance.</returns>
    public static TpmSessionInfo Create(
        string? manufacturer,
        string? firmwareVersion,
        TpmPlatform platform,
        TimeProvider timeProvider)
    {
        return new TpmSessionInfo(manufacturer, firmwareVersion, platform, timeProvider.GetUtcNow());
    }
}