using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm;

/// <summary>
/// Common Linux errno values used for TPM transport errors.
/// </summary>
/// <remarks>
/// <para>
/// These are standard POSIX error codes that may be returned when
/// communicating with /dev/tpmrm0 on Linux.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "These values follow standard POSIX error codes.")]
public enum LinuxErrno: uint
{
    /// <summary>
    /// EIO (5) - I/O error.
    /// </summary>
    EIO = 5,

    /// <summary>
    /// ENODEV (19) - No such device.
    /// </summary>
    ENODEV = 19,

    /// <summary>
    /// EINVAL (22) - Invalid argument.
    /// </summary>
    EINVAL = 22,

    /// <summary>
    /// EBUSY (16) - Device or resource busy.
    /// </summary>
    EBUSY = 16,

    /// <summary>
    /// EACCES (13) - Permission denied.
    /// </summary>
    EACCES = 13,

    /// <summary>
    /// ENOENT (2) - No such file or directory.
    /// </summary>
    ENOENT = 2
}
