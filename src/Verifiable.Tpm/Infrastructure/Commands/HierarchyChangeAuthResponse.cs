namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_HierarchyChangeAuth. This command has no response handles and no response parameters, so
/// the response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, clause 24.8 (Table 206).
/// </remarks>
public sealed class HierarchyChangeAuthResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static HierarchyChangeAuthResponse Instance { get; } = new();

    private HierarchyChangeAuthResponse()
    {
    }
}
