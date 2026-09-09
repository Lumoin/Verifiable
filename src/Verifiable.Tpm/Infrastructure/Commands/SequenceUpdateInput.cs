using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_SequenceUpdate command (CC = TPM_CC_SequenceUpdate, 0x0000015C).
/// </summary>
/// <remarks>
/// <para>
/// Adds <see cref="Buffer"/> to the sequence referenced by <see cref="SequenceHandle"/>. "buffer may be any
/// size up to the limits of the TPM. ... In all TPMs, a buffer size of 1,024 octets is allowed" (TPM 2.0
/// Library Part 3, clause 17.7), the bound <see cref="Tpm2bMaxBuffer.Create"/> enforces (its
/// <see cref="ArgumentException"/> is this command's TPM_RC_SIZE, raised before any pooled rental). "If the
/// command does not return TPM_RC_SUCCESS, the state of the sequence is unmodified."
/// </para>
/// <para>
/// <see cref="SequenceHandle"/> carries Auth Index 1 with Auth Role USER (Table 91), so the sequence's own
/// authorization value gates this call. "If an authorization or audit of this command requires computation
/// of a cpHash and an rpHash, the Name associated with sequenceHandle will be the Empty Buffer" (clause
/// 17.7) — a sequence object has no Name a TPM2B_NAME can carry.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 17.7, Table 91):
/// </para>
/// <list type="bullet">
///   <item><description>sequenceHandle (TPMI_DH_OBJECT, Auth Index 1, Auth Role USER): the sequence to extend. Requires the sequence's authorization value.</description></item>
///   <item><description>buffer (TPM2B_MAX_BUFFER): the data appended to the sequence.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SequenceUpdateInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SequenceUpdate;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>buffer</c> (<c>TPM2B_MAX_BUFFER</c>) is the only entry of the parameter area and carries an
    /// explicit size field (TPM 2.0 Library Part 3, clause 17.7, Table 91), which is what TPM 2.0 Library
    /// Part 1, clause 18.1 requires of an encryptable parameter and what clause 15.4 restates ("for a
    /// command or response parameter to be encrypted, it must be the first parameter and it must be a TPM2B
    /// type"). A session without the <c>decrypt</c> attribute is unaffected.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The sequence handle sits at position 0 of the handle area (TPM 2.0 Library Part 3, clause 17.7, Table 91), so its cpHash Name term is the Empty
    /// Buffer the executor derives (TPM 2.0 Library Part 1, clause 29.4.6).
    /// </summary>
    /// <param name="handleIndex">The zero-based position in the command's handle area.</param>
    /// <returns><see langword="true"/> for the sequence handle's position.</returns>
    public bool HandleIsSequence(int handleIndex) => handleIndex == 0;

    /// <summary>
    /// Gets the handle of the sequence being extended.
    /// </summary>
    public TpmiDhObject SequenceHandle { get; }

    /// <summary>
    /// Gets the data appended to the sequence. Owned storage: released by <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bMaxBuffer Buffer { get; }

    /// <summary>
    /// Creates a TPM2_SequenceUpdate input.
    /// </summary>
    /// <param name="sequenceHandle">The handle of the sequence being extended.</param>
    /// <param name="buffer">The data to append to the sequence, at most <see cref="Tpm2bMaxBuffer.MaxSize"/> octets.</param>
    /// <param name="pool">The memory pool for the buffer.</param>
    /// <returns>A new <see cref="SequenceUpdateInput"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="buffer"/> is longer than <see cref="Tpm2bMaxBuffer.MaxSize"/> — the caller-side TPM_RC_SIZE, raised before any pooled rental.</exception>
    public static SequenceUpdateInput Create(TpmiDhObject sequenceHandle, ReadOnlySpan<byte> buffer, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bMaxBuffer data = Tpm2bMaxBuffer.Create(buffer, pool);

        return new SequenceUpdateInput(sequenceHandle, data);
    }

    private SequenceUpdateInput(TpmiDhObject sequenceHandle, Tpm2bMaxBuffer buffer)
    {
        SequenceHandle = sequenceHandle;
        Buffer = buffer;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +          //sequenceHandle (TPMI_DH_OBJECT).
               Buffer.SerializedSize;  //buffer (TPM2B_MAX_BUFFER).
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

    /// <summary>The debugger's one-line rendering: the sequence handle and the buffer's octet count, never its octets.</summary>
    private string DebuggerDisplay => $"SequenceUpdateInput(Sequence={SequenceHandle}, Buffer={Buffer.Length} bytes)";
}
