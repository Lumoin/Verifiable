namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_PolicyRestart. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 11.2, Table 16.
/// </remarks>
public sealed class PolicyRestartResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static PolicyRestartResponse Instance { get; } = new();

    private PolicyRestartResponse()
    {
    }
}
