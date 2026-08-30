namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_NV_SetBits. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, Section 31.10 (Table 260).
/// </remarks>
public sealed class NvSetBitsResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static NvSetBitsResponse Instance { get; } = new();

    /// <summary>
    /// Prevents external construction: the parameterless response resolves to <see cref="Instance"/>.
    /// </summary>
    private NvSetBitsResponse()
    {
    }
}
