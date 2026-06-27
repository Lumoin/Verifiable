namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_NV_Write. This command has no response handles and no response parameters, so the response
/// is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 31.7 (Table 233).
/// </remarks>
public sealed class NvWriteResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static NvWriteResponse Instance { get; } = new();

    private NvWriteResponse()
    {
    }
}
