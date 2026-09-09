namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_ClearControl. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, clause 24.7 (Table 204).
/// </remarks>
public sealed class ClearControlResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static ClearControlResponse Instance { get; } = new();

    private ClearControlResponse()
    {
    }
}
