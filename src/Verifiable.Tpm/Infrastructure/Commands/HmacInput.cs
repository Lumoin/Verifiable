using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_HMAC command (CC = TPM_CC_HMAC, 0x00000155).
/// </summary>
/// <remarks>
/// <para>
/// Computes an HMAC over a single data buffer with a loaded HMAC key (a KEYEDHASH object built from
/// <see cref="TpmtPublic.CreateHmacKeyTemplate"/>) in one round trip (TPM 2.0 Library Part 3, clause 15.5.1).
/// The key must have the <c>sign</c> attribute SET and <c>restricted</c> CLEAR; a restricted key answers
/// <c>TPM_RC_ATTRIBUTES</c>. Data larger than the TPM's input buffer goes through an HMAC sequence instead
/// (<c>TPM2_HMAC_Start()</c>, <c>TPM2_SequenceUpdate()</c>, <c>TPM2_SequenceComplete()</c>).
/// </para>
/// <para>
/// Wire layout (Table 71): handle <c>@handle</c> (Auth Index 1, Auth Role USER — the HMAC key); parameters
/// <c>buffer</c> (TPM2B_MAX_BUFFER, encryptable as the first parameter — the HMAC data) then <c>hashAlg</c>
/// (TPMI_ALG_HASH+, the algorithm to use for the HMAC).
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 15.5, Table 71 - TPM2_HMAC.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HmacInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_HMAC;

    /// <inheritdoc/>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The handle of the loaded HMAC key (<c>@handle</c>, TPMI_DH_OBJECT; Auth Index 1, Auth Role USER).
    /// </summary>
    public TpmiDhObject Handle { get; }

    /// <summary>
    /// The data to HMAC (<c>buffer</c>, TPM2B_MAX_BUFFER; may be empty); owned by this input and released by
    /// <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bMaxBuffer Buffer { get; }

    /// <summary>The hash algorithm to use for the HMAC (<c>hashAlg</c>, TPMI_ALG_HASH+).</summary>
    public TpmiAlgHash HashAlg { get; }

    /// <summary>
    /// Creates an input that computes an HMAC over <paramref name="buffer"/> with <paramref name="handle"/>
    /// under <paramref name="hashAlg"/>.
    /// </summary>
    /// <param name="handle">The handle of the loaded HMAC key.</param>
    /// <param name="buffer">The data to HMAC (at most <see cref="Tpm2bMaxBuffer.MaxSize"/> octets).</param>
    /// <param name="hashAlg">The hash algorithm to use for the HMAC.</param>
    /// <param name="pool">The memory pool the data carrier is rented from.</param>
    /// <returns>The command input.</returns>
    public static HmacInput Create(TpmiDhObject handle, ReadOnlySpan<byte> buffer, TpmiAlgHash hashAlg, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bMaxBuffer data = Tpm2bMaxBuffer.Create(buffer, pool);

        return new HmacInput(handle, data, hashAlg);
    }

    /// <summary>
    /// Initializes the input over an already-rented data carrier, adopting its ownership.
    /// </summary>
    /// <param name="handle">The handle of the loaded HMAC key.</param>
    /// <param name="buffer">The owned data carrier.</param>
    /// <param name="hashAlg">The hash algorithm to use for the HMAC.</param>
    private HmacInput(TpmiDhObject handle, Tpm2bMaxBuffer buffer, TpmiAlgHash hashAlg)
    {
        Handle = handle;
        Buffer = buffer;
        HashAlg = hashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +           //@handle (TPMI_DH_OBJECT).
               Buffer.SerializedSize +  //buffer (TPM2B_MAX_BUFFER).
               sizeof(ushort);          //hashAlg (TPMI_ALG_HASH+).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        Handle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        Buffer.WriteTo(ref writer);
        writer.WriteUInt16((ushort)HashAlg.Value);
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
    private string DebuggerDisplay => $"HmacInput(Handle=0x{Handle.Value:X8}, Buffer={Buffer.Length} bytes, HashAlg={HashAlg.Value})";
}
