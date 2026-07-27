namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_ClockSet. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 29.2 (Table 205).
/// </remarks>
public sealed class ClockSetResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static ClockSetResponse Instance { get; } = new();

    private ClockSetResponse()
    {
    }
}
