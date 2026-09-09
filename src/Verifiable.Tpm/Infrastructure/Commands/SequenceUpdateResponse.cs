using System.Diagnostics;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_SequenceUpdate.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response parameter area for the TPM2_SequenceUpdate command. This
/// command has no response parameters beyond the standard header with response code.
/// </para>
/// <para>
/// <b>Response parameters (TPM 2.0 Library Part 3, clause 17.7, Table 92):</b> None.
/// </para>
/// <para>
/// <b>Note:</b> This type exists for consistency with other commands and to enable uniform handling in
/// generic code. A successful response indicates the sequence was extended.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SequenceUpdateResponse: ITpmWireType
{
    /// <summary>
    /// Gets the singleton instance.
    /// </summary>
    /// <remarks>
    /// Since this response has no data, a single instance can be reused.
    /// </remarks>
    public static SequenceUpdateResponse Instance { get; } = new();

    private SequenceUpdateResponse()
    {
    }

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <returns>The singleton response instance.</returns>
    /// <remarks>
    /// This method does not consume any bytes from the reader since TPM2_SequenceUpdate has no response
    /// parameters.
    /// </remarks>
    public static SequenceUpdateResponse Parse(ref TpmReader reader)
    {
        //No parameters to parse.
        return Instance;
    }

    private static string DebuggerDisplay => "SequenceUpdateResponse()";
}
