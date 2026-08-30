using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response to the TPM2_HMAC_Start command: the transient handle of the newly opened HMAC sequence context,
/// carried in the response handle area with no parameters (TPM 2.0 Library Part 3, clause 17.2, Table 81).
/// </summary>
/// <remarks>
/// The sequence context is a transient object addressed like any loaded object (Part 1, clause 27.2.3), fed by
/// <c>TPM2_SequenceUpdate()</c>, and released by a successful <c>TPM2_SequenceComplete()</c>, by
/// <c>TPM2_FlushContext()</c>, or by <c>TPM2_Startup()</c>.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HmacStartResponse: ITpmWireType
{
    /// <summary>The handle of the newly opened HMAC sequence context (<c>sequenceHandle</c>, TPMI_DH_OBJECT).</summary>
    public TpmiDhObject SequenceHandle { get; }

    /// <summary>Initializes the response over the already-parsed response handle.</summary>
    /// <param name="sequenceHandle">The sequence handle from the response handle area.</param>
    private HmacStartResponse(TpmiDhObject sequenceHandle)
    {
        SequenceHandle = sequenceHandle;
    }

    /// <summary>
    /// Parses the response parameters — of which Table 81 has none — after the executor has already consumed
    /// the response handle area.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameter area.</param>
    /// <param name="sequenceHandle">The sequence handle read from the response handle area.</param>
    /// <param name="pool">The memory pool (unused: nothing is rented).</param>
    /// <returns>The parsed response.</returns>
    public static HmacStartResponse Parse(ref TpmReader reader, TpmiDhObject sequenceHandle, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Table 81 has no response parameters: nothing is read from reader beyond the already-parsed handle.
        return new HmacStartResponse(sequenceHandle);
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"HmacStartResponse(SequenceHandle=0x{SequenceHandle.Value:X8})";
}
