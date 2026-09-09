namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_NV_ChangeAuth. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, clause 31.15 (Table 269/270).
/// </remarks>
public sealed class NvChangeAuthResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static NvChangeAuthResponse Instance { get; } = new();

    private NvChangeAuthResponse()
    {
    }
}
