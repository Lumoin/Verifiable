namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_PolicyCpHash. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, clause 23.13, Table 164.
/// </remarks>
public sealed class PolicyCpHashResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static PolicyCpHashResponse Instance { get; } = new();

    private PolicyCpHashResponse()
    {
    }
}
