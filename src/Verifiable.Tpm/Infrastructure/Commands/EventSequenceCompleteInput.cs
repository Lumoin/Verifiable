using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_EventSequenceComplete command (CC = TPM_CC_EventSequenceComplete, 0x00000185).
/// </summary>
/// <remarks>
/// <para>
/// "This command adds the last part of data, if any, to an Event Sequence and returns the result in a digest
/// list. If pcrHandle references a PCR and not TPM_RH_NULL, then the returned digest list is processed in the
/// same manner as the digest list input parameter to TPM2_PCR_Extend()" (TPM 2.0 Library Part 3, clause
/// 17.9.1). The Event Sequence is the one <c>TPM2_HashSequenceStart()</c> opened with <c>hashAlg</c> =
/// <c>TPM_ALG_NULL</c> and <c>TPM2_SequenceUpdate()</c> fed; a hash or HMAC sequence answers <c>TPM_RC_MODE</c>.
/// "If this command completes successfully, the sequenceHandle object will be flushed" (<c>{F}</c>).
/// </para>
/// <para>
/// Two authorizations (Table 95): <see cref="PcrHandle"/> at Auth Index 1 (USER — the PCR's EmptyAuth on a PC
/// Client TPM, PTP 1.07, clause 4.7, item 5) and <see cref="SequenceHandle"/> at Auth Index 2 (USER — the
/// sequence's own authValue, exempt from dictionary-attack protection, Part 1, clause 29.4.6). "If an
/// authorization or audit of this command requires computation of a cpHash and an rpHash, the Name associated
/// with sequenceHandle will be the Empty Buffer."
/// </para>
/// <para>
/// Wire layout (Table 95): handle area <c>@pcrHandle</c> (TPMI_DH_PCR+) then <c>@sequenceHandle</c>
/// (TPMI_DH_OBJECT); parameter <c>buffer</c> (TPM2B_MAX_BUFFER), the first parameter and a TPM2B, so
/// encryptable. The command is <c>{NV F}</c>.
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 17.9, Table 95 - TPM2_EventSequenceComplete.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class EventSequenceCompleteInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_EventSequenceComplete;

    /// <inheritdoc/>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The sequence handle sits at position 1 of the handle area (TPM 2.0 Library Part 3, clause 17.9, Table 95: <c>@pcrHandle</c> first, <c>@sequenceHandle</c> second), so its cpHash Name term is the Empty
    /// Buffer the executor derives (TPM 2.0 Library Part 1, clause 29.4.6).
    /// </summary>
    /// <param name="handleIndex">The zero-based position in the command's handle area.</param>
    /// <returns><see langword="true"/> for the sequence handle's position.</returns>
    public bool HandleIsSequence(int handleIndex) => handleIndex == 1;

    /// <summary>
    /// The register to extend with the event digests (<c>pcrHandle</c>, TPMI_DH_PCR+), or <c>TPM_RH_NULL</c>
    /// to only complete the sequence and return the digests.
    /// </summary>
    public TpmiDhPcr PcrHandle { get; }

    /// <summary>The open Event Sequence to complete (<c>sequenceHandle</c>, TPMI_DH_OBJECT).</summary>
    public TpmiDhObject SequenceHandle { get; }

    /// <summary>
    /// The last part of the event data, possibly empty (<c>buffer</c>, TPM2B_MAX_BUFFER); owned by this input
    /// and released by <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bMaxBuffer Buffer { get; }

    /// <summary>
    /// Creates an input completing <paramref name="sequenceHandle"/> with <paramref name="buffer"/> as its last
    /// block and extending <paramref name="pcrHandle"/>.
    /// </summary>
    /// <param name="pcrHandle">The register to extend, or <c>TPM_RH_NULL</c>.</param>
    /// <param name="sequenceHandle">The open Event Sequence.</param>
    /// <param name="buffer">The trailing block, possibly empty, at most <see cref="Tpm2bMaxBuffer.MaxSize"/>.</param>
    /// <param name="pool">The memory pool the buffer carrier is rented from.</param>
    /// <returns>The command input.</returns>
    /// <exception cref="ArgumentException"><paramref name="buffer"/> is longer than <see cref="Tpm2bMaxBuffer.MaxSize"/>.</exception>
    public static EventSequenceCompleteInput Create(TpmiDhPcr pcrHandle, TpmiDhObject sequenceHandle, ReadOnlySpan<byte> buffer, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bMaxBuffer carrier = Tpm2bMaxBuffer.Create(buffer, pool);

        return new EventSequenceCompleteInput(pcrHandle, sequenceHandle, carrier);
    }

    /// <summary>
    /// Initializes the input over an owned buffer carrier.
    /// </summary>
    /// <param name="pcrHandle">The register to extend.</param>
    /// <param name="sequenceHandle">The open Event Sequence.</param>
    /// <param name="buffer">The owned trailing block.</param>
    private EventSequenceCompleteInput(TpmiDhPcr pcrHandle, TpmiDhObject sequenceHandle, Tpm2bMaxBuffer buffer)
    {
        PcrHandle = pcrHandle;
        SequenceHandle = sequenceHandle;
        Buffer = buffer;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +          //pcrHandle (TPMI_DH_PCR+).
               sizeof(uint) +          //sequenceHandle (TPMI_DH_OBJECT).
               Buffer.SerializedSize;  //buffer (TPM2B_MAX_BUFFER).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        PcrHandle.WriteTo(ref writer);
        writer.WriteUInt32(SequenceHandle.Value);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        Buffer.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Buffer.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"EventSequenceCompleteInput(PcrHandle=0x{PcrHandle.Value:X8}, SequenceHandle=0x{SequenceHandle.Value:X8}, Buffer={Buffer.Length} bytes)";
}
