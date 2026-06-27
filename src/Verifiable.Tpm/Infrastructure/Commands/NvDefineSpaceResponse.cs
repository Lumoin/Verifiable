namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_NV_DefineSpace. This command has no response handles and no response parameters,
/// so the response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 31.3 (Table 229).
/// </remarks>
public sealed class NvDefineSpaceResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static NvDefineSpaceResponse Instance { get; } = new();

    private NvDefineSpaceResponse()
    {
    }
}
