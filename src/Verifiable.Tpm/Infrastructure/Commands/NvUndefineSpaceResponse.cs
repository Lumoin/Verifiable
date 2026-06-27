namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_NV_UndefineSpace. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 31.4 (Table 231).
/// </remarks>
public sealed class NvUndefineSpaceResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static NvUndefineSpaceResponse Instance { get; } = new();

    private NvUndefineSpaceResponse()
    {
    }
}
