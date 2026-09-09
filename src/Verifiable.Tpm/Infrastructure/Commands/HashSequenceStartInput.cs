using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_HashSequenceStart command (CC = TPM_CC_HashSequenceStart, 0x00000186).
/// </summary>
/// <remarks>
/// <para>
/// Starts a hash sequence when <see cref="HashAlg"/> is an implemented hash algorithm, or an Event Sequence
/// when it is <c>TPM_ALG_NULL</c> (TPM 2.0 Library Part 3, clause 17.4.1). The TPM assigns the new sequence
/// context a transient handle and sets its authValue to <see cref="Auth"/>, which every later
/// <c>TPM2_SequenceUpdate()</c>, <c>TPM2_SequenceComplete()</c>, or <c>TPM2_EventSequenceComplete()</c> on
/// the sequence must present (Part 1, clause 29.4).
/// </para>
/// <para>
/// Wire layout (Part 3, Table 85): no handles; parameters <c>auth</c> (TPM2B_AUTH) then <c>hashAlg</c>
/// (TPMI_ALG_HASH+). The command has no authorization area of its own, so it is framed
/// <c>TPM_ST_NO_SESSIONS</c> unless an audit or decrypt session is present. <c>auth</c> is the first
/// parameter and is encryptable.
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 17.4, Table 85 - TPM2_HashSequenceStart.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HashSequenceStartInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_HashSequenceStart;

    /// <inheritdoc/>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The authorization value the started sequence is protected by (<c>auth</c>, TPM2B_AUTH); owned by this
    /// input and released by <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bAuth Auth { get; }

    /// <summary>
    /// The hash algorithm of the sequence (<c>hashAlg</c>, TPMI_ALG_HASH+): an implemented hash starts a hash
    /// sequence; <c>TPM_ALG_NULL</c> starts an Event Sequence.
    /// </summary>
    public TpmiAlgHash HashAlg { get; }

    /// <summary>
    /// Creates an input that starts a hash sequence under <paramref name="hashAlg"/>, or an Event Sequence
    /// when <paramref name="hashAlg"/> is <c>TPM_ALG_NULL</c>, protected by <paramref name="sequenceAuth"/>.
    /// </summary>
    /// <param name="sequenceAuth">The sequence's authorization value (may be empty).</param>
    /// <param name="hashAlg">The sequence's hash algorithm, or <c>TPM_ALG_NULL</c> for an Event Sequence.</param>
    /// <param name="pool">The memory pool the authorization carrier is rented from.</param>
    /// <returns>The command input.</returns>
    public static HashSequenceStartInput Create(ReadOnlySpan<byte> sequenceAuth, TpmiAlgHash hashAlg, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth auth = Tpm2bAuth.Create(sequenceAuth, pool);

        return new HashSequenceStartInput(auth, hashAlg);
    }

    /// <summary>
    /// Creates an input whose sequence authorization value is the UTF-8 encoding of
    /// <paramref name="sequencePassword"/>.
    /// </summary>
    /// <param name="sequencePassword">The sequence's password.</param>
    /// <param name="hashAlg">The sequence's hash algorithm, or <c>TPM_ALG_NULL</c> for an Event Sequence.</param>
    /// <param name="pool">The memory pool the authorization carrier is rented from.</param>
    /// <returns>The command input.</returns>
    public static HashSequenceStartInput CreateFromPassword(string sequencePassword, TpmiAlgHash hashAlg, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth auth = Tpm2bAuth.CreateFromPassword(sequencePassword, pool);

        return new HashSequenceStartInput(auth, hashAlg);
    }

    /// <summary>
    /// Initializes the input over an already-rented authorization carrier, adopting its ownership.
    /// </summary>
    /// <param name="auth">The owned authorization carrier.</param>
    /// <param name="hashAlg">The sequence's hash algorithm.</param>
    private HashSequenceStartInput(Tpm2bAuth auth, TpmiAlgHash hashAlg)
    {
        Auth = auth;
        HashAlg = hashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return Auth.SerializedSize + //auth (TPM2B_AUTH).
               sizeof(ushort);       //hashAlg (TPMI_ALG_HASH+).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //Table 85 has no handle area.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        Auth.WriteTo(ref writer);
        writer.WriteUInt16((ushort)HashAlg.Value);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Auth.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"HashSequenceStartInput(HashAlg={HashAlg.Value}, Auth={Auth.Length} bytes)";
}
