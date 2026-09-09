namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_NV_ReadLock. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 31.14 (Table 268).
/// </remarks>
public sealed class NvReadLockResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static NvReadLockResponse Instance { get; } = new();

    /// <summary>
    /// Prevents external construction: the parameterless response resolves to <see cref="Instance"/>.
    /// </summary>
    private NvReadLockResponse()
    {
    }
}
