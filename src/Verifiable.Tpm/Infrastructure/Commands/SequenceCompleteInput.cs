using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_SequenceComplete command (CC = TPM_CC_SequenceComplete, 0x0000013E).
/// </summary>
/// <remarks>
/// <para>
/// Adds the last part of the data, if any, to a hash or HMAC sequence and returns the digest or HMAC together
/// with a <c>TPMT_TK_HASHCHECK</c> ticket (TPM 2.0 Library Part 3, clause 17.8.1). For a hash sequence the
/// ticket, minted under the proof of <see cref="Hierarchy"/>, attests that the hashed octets did not begin with
/// <c>TPM_GENERATED_VALUE</c>, so the digest may be signed with a restricted signing key
/// (<c>TPM2_SignDigest()</c>, clause 20.7); it is the NULL Ticket when <see cref="Hierarchy"/> is
/// <c>TPM_RH_NULL</c>, when the first block was not safe to sign, or when the sequence is an HMAC sequence. An
/// Event Sequence cannot be completed by this command (<c>TPM_RC_MODE</c>); <c>TPM2_EventSequenceComplete()</c>
/// is used for that purpose. On success the sequence context is flushed (<c>{F}</c>, Table 93).
/// </para>
/// <para>
/// Wire layout (Table 93): handle <c>@sequenceHandle</c> (TPMI_DH_OBJECT, Auth Index 1, USER role — the
/// sequence's own authValue, exempt from dictionary-attack protection per Part 1, clause 29.4.6); parameters
/// <c>buffer</c> (TPM2B_MAX_BUFFER, the trailing data, encryptable as the first parameter) then
/// <c>hierarchy</c> (TPMI_RH_HIERARCHY, the ticket's hierarchy).
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 17.8, Table 93 - TPM2_SequenceComplete.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SequenceCompleteInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SequenceComplete;

    /// <inheritdoc/>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The sequence handle sits at position 0 of the handle area (TPM 2.0 Library Part 3, clause 17.8, Table 93), so its cpHash Name term is the Empty
    /// Buffer the executor derives (TPM 2.0 Library Part 1, clause 29.4.6).
    /// </summary>
    /// <param name="handleIndex">The zero-based position in the command's handle area.</param>
    /// <returns><see langword="true"/> for the sequence handle's position.</returns>
    public bool HandleIsSequence(int handleIndex) => handleIndex == 0;

    /// <summary>The handle of the open sequence to complete (<c>@sequenceHandle</c>).</summary>
    public TpmiDhObject SequenceHandle { get; }

    /// <summary>
    /// The trailing data appended to the sequence before it is completed (<c>buffer</c>, TPM2B_MAX_BUFFER;
    /// may be empty); owned by this input and released by <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bMaxBuffer Buffer { get; }

    /// <summary>
    /// The hierarchy whose proof integrity-protects the returned ticket (<c>hierarchy</c>, TPMI_RH_HIERARCHY);
    /// <c>TPM_RH_NULL</c> requests no ticket.
    /// </summary>
    public TpmiRhHierarchy Hierarchy { get; }

    /// <summary>
    /// Creates an input that completes <paramref name="sequenceHandle"/> with <paramref name="buffer"/> as
    /// its last data, requesting a ticket under <paramref name="hierarchy"/>.
    /// </summary>
    /// <param name="sequenceHandle">The open sequence's handle.</param>
    /// <param name="buffer">The trailing data (may be empty).</param>
    /// <param name="hierarchy">The ticket hierarchy, or <c>TPM_RH_NULL</c> for no ticket.</param>
    /// <param name="pool">The memory pool the buffer carrier is rented from.</param>
    /// <returns>The command input.</returns>
    public static SequenceCompleteInput Create(TpmiDhObject sequenceHandle, ReadOnlySpan<byte> buffer, TpmiRhHierarchy hierarchy, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bMaxBuffer data = Tpm2bMaxBuffer.Create(buffer, pool);

        return new SequenceCompleteInput(sequenceHandle, data, hierarchy);
    }

    /// <summary>
    /// Initializes the input over an already-rented buffer carrier, adopting its ownership.
    /// </summary>
    /// <param name="sequenceHandle">The open sequence's handle.</param>
    /// <param name="buffer">The owned trailing-data carrier.</param>
    /// <param name="hierarchy">The ticket hierarchy.</param>
    private SequenceCompleteInput(TpmiDhObject sequenceHandle, Tpm2bMaxBuffer buffer, TpmiRhHierarchy hierarchy)
    {
        SequenceHandle = sequenceHandle;
        Buffer = buffer;
        Hierarchy = hierarchy;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +          //sequenceHandle (TPMI_DH_OBJECT).
               Buffer.SerializedSize + //buffer (TPM2B_MAX_BUFFER).
               sizeof(uint);           //hierarchy (TPMI_RH_HIERARCHY).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        SequenceHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        Buffer.WriteTo(ref writer);
        Hierarchy.WriteTo(ref writer);
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
    private string DebuggerDisplay => $"SequenceCompleteInput(Sequence={SequenceHandle}, Buffer={Buffer.Length} bytes, Hierarchy=0x{Hierarchy.Value:X8})";
}
