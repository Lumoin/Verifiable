namespace Verifiable.Tpm.Extensions.EventLog;

/// <summary>
/// Error codes specific to TCG event log reading operations.
/// </summary>
/// <remarks>
/// <para>
/// These error codes are returned as transport errors in <see cref="TpmResult{T}"/>
/// when reading the event log fails. They use a distinct range (0x80291000) to avoid
/// collision with TBS, TPM, and parser error codes.
/// </para>
/// <para>
/// For Windows TBS errors, the actual <see cref="TbsResult"/> value is returned directly.
/// For Linux file errors, the <see cref="LinuxErrno"/> value is returned.
/// </para>
/// </remarks>
public enum TcgEventLogReaderError: uint
{
    /// <summary>
    /// The current platform is not supported for event log reading.
    /// </summary>
    PlatformNotSupported = 0x80291001,

    /// <summary>
    /// Linux: The securityfs filesystem is not mounted at /sys/kernel/security.
    /// </summary>
    SecurityFsNotMounted = 0x80291002,

    /// <summary>
    /// Linux: No TPM device found at /sys/kernel/security/tpm0.
    /// </summary>
    TpmNotFound = 0x80291003,

    /// <summary>
    /// The event log file or interface is not available.
    /// </summary>
    EventLogNotAvailable = 0x80291004
}

/// <summary>
/// Extension methods for <see cref="TcgEventLogReaderError"/>.
/// </summary>
public static class TcgEventLogReaderErrorExtensions
{
    /// <summary>
    /// Gets a human-readable description of the error code.
    /// </summary>
    public static string GetDescription(this TcgEventLogReaderError error)
    {
        return error switch
        {
            TcgEventLogReaderError.PlatformNotSupported => "The current platform is not supported for event log reading.",
            TcgEventLogReaderError.SecurityFsNotMounted => "The securityfs filesystem is not mounted. Try: mount -t securityfs securityfs /sys/kernel/security",
            TcgEventLogReaderError.TpmNotFound => "No TPM device found in securityfs.",
            TcgEventLogReaderError.EventLogNotAvailable => "The event log file or interface is not available.",
            _ => $"Unknown event log reader error: 0x{(uint)error:X8}"
        };
    }
}