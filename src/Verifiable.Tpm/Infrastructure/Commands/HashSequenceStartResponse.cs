using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response to the TPM2_HashSequenceStart command: the transient handle of the newly opened hash or Event
/// Sequence context, carried in the response handle area with no parameters (TPM 2.0 Library Part 3, clause
/// 17.4, Table 86).
/// </summary>
/// <remarks>
/// The sequence context is a transient object addressed like any loaded object (Part 1, clause 27.2.3), fed by
/// <c>TPM2_SequenceUpdate()</c>, and released by a successful <c>TPM2_SequenceComplete()</c> (a hash sequence)
/// or <c>TPM2_EventSequenceComplete()</c> (an Event Sequence), by <c>TPM2_FlushContext()</c>, or by
/// <c>TPM2_Startup()</c>. Its public portion is not readable with <c>TPM2_ReadPublic()</c>, which answers
/// <c>TPM_RC_SEQUENCE</c> for it (clause 12.4).
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HashSequenceStartResponse: ITpmWireType
{
    /// <summary>The handle of the newly opened sequence context (<c>sequenceHandle</c>, TPMI_DH_OBJECT).</summary>
    public TpmiDhObject SequenceHandle { get; }

    /// <summary>Initializes the response over the already-parsed response handle.</summary>
    /// <param name="sequenceHandle">The sequence handle from the response handle area.</param>
    private HashSequenceStartResponse(TpmiDhObject sequenceHandle)
    {
        SequenceHandle = sequenceHandle;
    }

    /// <summary>
    /// Parses the response parameters — of which Table 86 has none — after the executor has already consumed
    /// the response handle area.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameter area.</param>
    /// <param name="sequenceHandle">The sequence handle read from the response handle area.</param>
    /// <param name="pool">The memory pool (unused: nothing is rented).</param>
    /// <returns>The parsed response.</returns>
    public static HashSequenceStartResponse Parse(ref TpmReader reader, TpmiDhObject sequenceHandle, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        //Table 86 has no response parameters: nothing is read from reader beyond the already-parsed handle.
        return new HashSequenceStartResponse(sequenceHandle);
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"HashSequenceStartResponse(SequenceHandle=0x{SequenceHandle.Value:X8})";
}
