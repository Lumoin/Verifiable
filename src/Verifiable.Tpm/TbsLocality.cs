namespace Verifiable.Tpm;

/// <summary>
/// TBS command locality values.
/// </summary>
/// <remarks>
/// <para>
/// Locality determines the privilege level for TPM commands. Most applications
/// use Locality 0. Higher localities are used by special system components.
/// </para>
/// <para>
/// See <see href="https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsip_submit_command">
/// Tbsip_Submit_Command</see>.
/// </para>
/// </remarks>
public enum TbsLocality: uint
{
    /// <summary>
    /// Locality 0 - default locality for user-mode applications.
    /// </summary>
    Zero = 0,

    /// <summary>
    /// Locality 1 - typically used by platform firmware.
    /// </summary>
    One = 1,

    /// <summary>
    /// Locality 2 - typically used by runtime firmware.
    /// </summary>
    Two = 2,

    /// <summary>
    /// Locality 3 - typically used by the OS kernel.
    /// </summary>
    Three = 3,

    /// <summary>
    /// Locality 4 - typically used by trusted applications.
    /// </summary>
    Four = 4
}
