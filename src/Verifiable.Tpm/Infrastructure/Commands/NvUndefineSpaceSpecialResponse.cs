namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_NV_UndefineSpaceSpecial. This command has no response handles and no response parameters,
/// so the response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, clause 31.5 (Table 250).
/// </remarks>
public sealed class NvUndefineSpaceSpecialResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static NvUndefineSpaceSpecialResponse Instance { get; } = new();

    /// <summary>
    /// Prevents external construction: the parameterless response resolves to <see cref="Instance"/>.
    /// </summary>
    private NvUndefineSpaceSpecialResponse()
    {
    }
}
