using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response to the TPM2_PCR_Extend command: no parameters beyond the header (TPM 2.0 Library Part 3, clause
/// 22.2, Table 131).
/// </summary>
/// <remarks>
/// A successful response means every listed digest whose bank is implemented has been extended into the named
/// register and <c>pcrUpdateCounter</c> has moved for each counted extend. The type exists so the command has
/// a codec like every other, and since it carries nothing a single instance serves every response.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PcrExtendResponse: ITpmWireType
{
    /// <summary>
    /// Gets the singleton instance every parse returns.
    /// </summary>
    public static PcrExtendResponse Instance { get; } = new();

    /// <summary>Initializes the singleton.</summary>
    private PcrExtendResponse()
    {
    }

    /// <summary>
    /// Parses the (empty) response parameters; consumes nothing from <paramref name="reader"/>.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <returns>The singleton response instance.</returns>
    public static PcrExtendResponse Parse(ref TpmReader reader)
    {
        //Table 131 has no response parameters.
        return Instance;
    }

    /// <summary>The debugger display string.</summary>
    private static string DebuggerDisplay => "PcrExtendResponse()";
}
