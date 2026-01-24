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
    Linux,

    /// <summary>
    /// Virtual platform using delegate-based handler.
    /// </summary>
    /// <remarks>
    /// Used when <see cref="TpmDevice"/> is created via <see cref="TpmDevice.Create"/>
    /// with a custom <see cref="TpmSubmitHandler"/> delegate.
    /// </remarks>
    Virtual
}