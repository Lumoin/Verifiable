using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_FlushContext.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response parameter area for the
/// TPM2_FlushContext command. This command has no response parameters
/// beyond the standard header with response code.
/// </para>
/// <para>
/// <b>Response parameters (Part 3, Section 28.4):</b> None.
/// </para>
/// <para>
/// <b>Note:</b> This type exists for consistency with other commands and
/// to enable uniform handling in generic code. A successful response
/// indicates the context was flushed.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class FlushContextResponse: ITpmWireType
{
    /// <summary>
    /// Gets the singleton instance.
    /// </summary>
    /// <remarks>
    /// Since this response has no data, a single instance can be reused.
    /// </remarks>
    public static FlushContextResponse Instance { get; } = new();

    private FlushContextResponse()
    {
    }

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <returns>The singleton response instance.</returns>
    /// <remarks>
    /// This method does not consume any bytes from the reader since
    /// FlushContext has no response parameters.
    /// </remarks>
    public static FlushContextResponse Parse(ref TpmReader reader)
    {
        //No parameters to parse.
        return Instance;
    }

    private string DebuggerDisplay => "FlushContextResponse()";
}