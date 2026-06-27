namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_EvictControl. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 28.5 (Table 197).
/// </remarks>
public sealed class EvictControlResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static EvictControlResponse Instance { get; } = new();

    private EvictControlResponse()
    {
    }
}
