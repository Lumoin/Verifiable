namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_StirRandom. This command has no response handles and no response parameters, so the
/// response is the 10-byte header alone.
/// </summary>
/// <remarks>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 16.2 (Table 78).
/// </remarks>
public sealed class StirRandomResponse: ITpmWireType
{
    /// <summary>
    /// The shared instance returned for a successful, parameterless response.
    /// </summary>
    public static StirRandomResponse Instance { get; } = new();

    /// <summary>
    /// Prevents external construction: the parameterless response resolves to <see cref="Instance"/>.
    /// </summary>
    private StirRandomResponse()
    {
    }
}
