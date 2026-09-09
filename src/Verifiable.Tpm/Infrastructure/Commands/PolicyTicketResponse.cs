namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_PolicyTicket. This command has no response handles and no response parameters (Table 149),
/// so the response is the 10-byte header alone — symmetric with TPM2_PolicyAuthorize's response shape.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, clause 23.5.
/// </remarks>
public sealed class PolicyTicketResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static PolicyTicketResponse Instance { get; } = new();

    private PolicyTicketResponse()
    {
    }
}
