using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response to the TPM2_PCR_Reset command: no parameters beyond the header (TPM 2.0 Library Part 3, clause
/// 22.8, Table 143).
/// </summary>
/// <remarks>
/// A successful response means the named register reads all zeros in every bank. The type exists so the
/// command has a codec like every other, and since it carries nothing a single instance serves every
/// response.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PcrResetResponse: ITpmWireType
{
    /// <summary>
    /// Gets the singleton instance every parse returns.
    /// </summary>
    public static PcrResetResponse Instance { get; } = new();

    /// <summary>Initializes the singleton.</summary>
    private PcrResetResponse()
    {
    }

    /// <summary>
    /// Parses the (empty) response parameters; consumes nothing from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <returns>The singleton response instance.</returns>
    public static PcrResetResponse Parse(ref TpmReader reader)
    {
        //Table 143 has no response parameters.
        return Instance;
    }

    /// <summary>The debugger display string.</summary>
    private static string DebuggerDisplay => "PcrResetResponse()";
}
