namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_PolicyNameHash. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 23.14, Table 166.
/// </remarks>
public sealed class PolicyNameHashResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static PolicyNameHashResponse Instance { get; } = new();

    private PolicyNameHashResponse()
    {
    }
}
