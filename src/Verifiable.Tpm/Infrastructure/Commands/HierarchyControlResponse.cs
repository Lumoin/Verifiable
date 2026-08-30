namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_HierarchyControl. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 24.2 (Table 194).
/// </remarks>
public sealed class HierarchyControlResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static HierarchyControlResponse Instance { get; } = new();

    private HierarchyControlResponse()
    {
    }
}
