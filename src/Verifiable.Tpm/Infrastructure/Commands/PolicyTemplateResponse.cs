namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_PolicyTemplate. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 23.21, Table 180.
/// </remarks>
public sealed class PolicyTemplateResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static PolicyTemplateResponse Instance { get; } = new();

    private PolicyTemplateResponse()
    {
    }
}
