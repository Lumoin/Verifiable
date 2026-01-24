namespace Verifiable.Tpm;

/// <summary>
/// Platform on which the TPM is accessed.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see> for platform-specific access mechanisms.
/// </para>
/// </remarks>
public enum TpmPlatform
{
    /// <summary>
    /// Platform could not be determined.
    /// </summary>
    Unknown,

    /// <summary>
    /// Windows platform using TBS API.
    /// </summary>
    Windows,

    /// <summary>
    /// Linux platform using /dev/tpmrm0.
    /// </summary>
    Linux
}