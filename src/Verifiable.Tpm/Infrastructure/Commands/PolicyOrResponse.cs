namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_PolicyOR. This command has no response handles and no response parameters, so the response
/// is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 23.6.
/// </remarks>
public sealed class PolicyOrResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static PolicyOrResponse Instance { get; } = new();

    private PolicyOrResponse()
    {
    }
}
