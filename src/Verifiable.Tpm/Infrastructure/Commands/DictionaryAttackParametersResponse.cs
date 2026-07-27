namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_DictionaryAttackParameters. This command has no response handles and no response
/// parameters, so the response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See TPM 2.0 Library Part 3, Section 25.3 (Table 183).
/// </remarks>
public sealed class DictionaryAttackParametersResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static DictionaryAttackParametersResponse Instance { get; } = new();

    private DictionaryAttackParametersResponse()
    {
    }
}
