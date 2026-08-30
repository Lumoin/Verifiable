using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_VerifySequenceStart.
/// </summary>
/// <remarks>
/// <para>
/// <b>Response handle (TPM 2.0 Library Part 3, clause 17.6, Table 90):</b>
/// </para>
/// <list type="bullet">
///   <item><description>sequenceHandle (TPMI_DH_OBJECT) - the handle of the newly opened sequence object.</description></item>
/// </list>
/// <para>
/// <b>Response parameters:</b> None — Table 90 carries only the handle area.
/// </para>
/// <para>
/// The returned handle references a sequence object, not a loaded key or a sealed object: it is not
/// readable with TPM2_ReadPublic() (which answers TPM_RC_SEQUENCE for it, clause 12.4), and it is released
/// only by TPM2_VerifySequenceComplete() succeeding, TPM2_FlushContext(), or TPM2_Startup().
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class VerifySequenceStartResponse: ITpmWireType
{
    /// <summary>
    /// Gets the handle of the newly opened verification sequence.
    /// </summary>
    public TpmiDhObject SequenceHandle { get; }

    /// <summary>
    /// Initializes a new instance with the specified sequence handle.
    /// </summary>
    /// <param name="sequenceHandle">The handle of the newly opened verification sequence.</param>
    private VerifySequenceStartResponse(TpmiDhObject sequenceHandle)
    {
        SequenceHandle = sequenceHandle;
    }

    /// <summary>
    /// Parses the response from handle and parameter data.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="sequenceHandle">The sequence handle from the response handle area.</param>
    /// <param name="pool">The memory pool for allocations. Unused: Table 90 carries no parameters, so this response rents nothing; the parameter is retained for parity with every other <see cref="TpmResponseParserWithHandle{TResponse}"/> delegate.</param>
    /// <returns>The parsed response.</returns>
    public static VerifySequenceStartResponse Parse(ref TpmReader reader, TpmiDhObject sequenceHandle, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Table 90 has no response parameters: nothing is read from reader beyond the already-parsed handle.
        return new VerifySequenceStartResponse(sequenceHandle);
    }

    /// <summary>The debugger's one-line rendering: the newly opened sequence handle.</summary>
    private string DebuggerDisplay => $"VerifySequenceStartResponse(SequenceHandle=0x{SequenceHandle.Value:X8})";
}
