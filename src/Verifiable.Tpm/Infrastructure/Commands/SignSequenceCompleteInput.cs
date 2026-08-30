using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_SignSequenceComplete command (CC = TPM_CC_SignSequenceComplete, 0x000001A4).
/// </summary>
/// <remarks>
/// <para>
/// Appends <see cref="Buffer"/> to the sequence referenced by <see cref="SequenceHandle"/> before hashing
/// and signing it with the key referenced by <see cref="KeyHandle"/> — "data to be added to the signature"
/// (TPM 2.0 Library Part 3, clause 20.6, Table 124), so a one-buffer message needs no prior
/// TPM2_SequenceUpdate() call and <see cref="Buffer"/> may be <see cref="Tpm2bMaxBuffer.Empty"/> when every
/// octet was already presented through updates. "Is like TPM2_Sign()" with no <c>inScheme</c>: "Overriding
/// the scheme of the key is not supported" — the key's own retained scheme and hash algorithm apply. There
/// is no validation ticket parameter; a restricted key is admitted only when the accumulated message does
/// not begin with TPM_GENERATED_VALUE (clause 20.6). "The x509sign attribute of keyHandle must not be SET"
/// or the TPM returns TPM_RC_ATTRIBUTES. On success the sequence context is flushed (TPM 2.0 Library Part 1,
/// clause 29.4.6: "{F}").
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 20.6, Table 124):
/// </para>
/// <list type="bullet">
///   <item><description>sequenceHandle (TPMI_DH_OBJECT, Auth Index 1, Auth Role USER): the sequence to complete and consume. Requires the sequence's authorization value.</description></item>
///   <item><description>keyHandle (TPMI_DH_OBJECT, Auth Index 2, Auth Role USER): the signing key. Requires the key's authorization.</description></item>
///   <item><description>buffer (TPM2B_MAX_BUFFER): the final data appended to the sequence before signing.</description></item>
/// </list>
/// <para>
/// The two handles' Auth Index order (sequence first, key second) fixes the order a caller passes sessions
/// to the executor: the session at index 0 authorizes <see cref="SequenceHandle"/>, the session at index 1
/// authorizes <see cref="KeyHandle"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SignSequenceCompleteInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SignSequenceComplete;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>buffer</c> (<c>TPM2B_MAX_BUFFER</c>) is the first entry of the parameter area and carries an
    /// explicit size field (TPM 2.0 Library Part 3, clause 20.6, Table 124), which is what TPM 2.0 Library
    /// Part 1, clause 18.1 requires of an encryptable parameter and what clause 15.4 restates ("for a
    /// command or response parameter to be encrypted, it must be the first parameter and it must be a TPM2B
    /// type"). A session without the <c>decrypt</c> attribute is unaffected.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The sequence handle sits at position 0 of the handle area (TPM 2.0 Library Part 3, clause 20.6, Table 124: <c>@sequenceHandle</c> first, <c>@keyHandle</c> second), so its cpHash Name term is the Empty
    /// Buffer the executor derives (TPM 2.0 Library Part 1, clause 29.4.6).
    /// </summary>
    /// <param name="handleIndex">The zero-based position in the command's handle area.</param>
    /// <returns><see langword="true"/> for the sequence handle's position.</returns>
    public bool HandleIsSequence(int handleIndex) => handleIndex == 0;

    /// <summary>
    /// Gets the handle of the sequence to complete and consume.
    /// </summary>
    public TpmiDhObject SequenceHandle { get; }

    /// <summary>
    /// Gets the handle of the signing key.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Gets the final data appended to the sequence before signing. Owned storage: released by
    /// <see cref="Dispose"/>. May be <see cref="Tpm2bMaxBuffer.Empty"/> when the message was already fully
    /// presented through prior TPM2_SequenceUpdate() calls.
    /// </summary>
    public Tpm2bMaxBuffer Buffer { get; }

    /// <summary>
    /// Creates a TPM2_SignSequenceComplete input.
    /// </summary>
    /// <param name="sequenceHandle">The handle of the sequence to complete and consume.</param>
    /// <param name="keyHandle">The handle of the signing key.</param>
    /// <param name="buffer">The final data to append to the sequence before signing, at most <see cref="Tpm2bMaxBuffer.MaxSize"/> octets. May be empty.</param>
    /// <param name="pool">The memory pool for the buffer.</param>
    /// <returns>A new <see cref="SignSequenceCompleteInput"/>.</returns>
    /// <exception cref="ArgumentException"><paramref name="buffer"/> is longer than <see cref="Tpm2bMaxBuffer.MaxSize"/> — the caller-side TPM_RC_SIZE, raised before any pooled rental.</exception>
    public static SignSequenceCompleteInput Create(
        TpmiDhObject sequenceHandle,
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> buffer,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bMaxBuffer data = Tpm2bMaxBuffer.Create(buffer, pool);

        return new SignSequenceCompleteInput(sequenceHandle, keyHandle, data);
    }

    private SignSequenceCompleteInput(TpmiDhObject sequenceHandle, TpmiDhObject keyHandle, Tpm2bMaxBuffer buffer)
    {
        SequenceHandle = sequenceHandle;
        KeyHandle = keyHandle;
        Buffer = buffer;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +          //sequenceHandle (TPMI_DH_OBJECT).
               sizeof(uint) +          //keyHandle (TPMI_DH_OBJECT).
               Buffer.SerializedSize;  //buffer (TPM2B_MAX_BUFFER).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        SequenceHandle.WriteTo(ref writer);
        KeyHandle.WriteTo(ref writer);
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

    /// <summary>The debugger's one-line rendering: both handles and the buffer's octet count, never its octets.</summary>
    private string DebuggerDisplay => $"SignSequenceCompleteInput(Sequence={SequenceHandle}, Key={KeyHandle}, Buffer={Buffer.Length} bytes)";
}
