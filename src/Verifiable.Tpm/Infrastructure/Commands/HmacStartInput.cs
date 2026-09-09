using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_HMAC_Start command (CC = TPM_CC_HMAC_Start, 0x0000015B).
/// </summary>
/// <remarks>
/// <para>
/// Starts an HMAC sequence over a loaded HMAC key (a KEYEDHASH object built from
/// <see cref="TpmtPublic.CreateHmacKeyTemplate"/>). The TPM assigns the new sequence context a transient
/// handle and sets its authValue to <see cref="Auth"/>, which every later <c>TPM2_SequenceUpdate()</c> or
/// <c>TPM2_SequenceComplete()</c> on the sequence must present (TPM 2.0 Library Part 3, clause 17.2.1).
/// </para>
/// <para>
/// Wire layout (Table 80): handle <c>@handle</c> (Auth Index 1, Auth Role USER — the HMAC key); parameters
/// <c>auth</c> (TPM2B_AUTH, encryptable as the first parameter) then <c>hashAlg</c> (TPMI_ALG_HASH+, the hash
/// used for the HMAC).
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 17.2, Table 80 - TPM2_HMAC_Start.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class HmacStartInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_HMAC_Start;

    /// <inheritdoc/>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// The handle of the loaded HMAC key (<c>@handle</c>, TPMI_DH_OBJECT; Auth Index 1, Auth Role USER).
    /// </summary>
    public TpmiDhObject Handle { get; }

    /// <summary>
    /// The authorization value the started sequence is protected by (<c>auth</c>, TPM2B_AUTH); owned by this
    /// input and released by <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bAuth Auth { get; }

    /// <summary>
    /// The hash algorithm the HMAC is computed with (<c>hashAlg</c>, TPMI_ALG_HASH+).
    /// </summary>
    public TpmiAlgHash HashAlg { get; }

    /// <summary>
    /// Creates an input that starts an HMAC sequence over <paramref name="handle"/>, protected by
    /// <paramref name="sequenceAuth"/>.
    /// </summary>
    /// <param name="handle">The handle of the loaded HMAC key.</param>
    /// <param name="sequenceAuth">The sequence's authorization value (may be empty).</param>
    /// <param name="hashAlg">The hash algorithm to use for the HMAC.</param>
    /// <param name="pool">The memory pool the authorization carrier is rented from.</param>
    /// <returns>The command input.</returns>
    public static HmacStartInput Create(TpmiDhObject handle, ReadOnlySpan<byte> sequenceAuth, TpmiAlgHash hashAlg, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth auth = Tpm2bAuth.Create(sequenceAuth, pool);

        return new HmacStartInput(handle, auth, hashAlg);
    }

    /// <summary>
    /// Creates an input whose sequence authorization value is the UTF-8 encoding of
    /// <paramref name="sequencePassword"/>.
    /// </summary>
    /// <param name="handle">The handle of the loaded HMAC key.</param>
    /// <param name="sequencePassword">The sequence's password.</param>
    /// <param name="hashAlg">The hash algorithm to use for the HMAC.</param>
    /// <param name="pool">The memory pool the authorization carrier is rented from.</param>
    /// <returns>The command input.</returns>
    public static HmacStartInput CreateFromPassword(TpmiDhObject handle, string sequencePassword, TpmiAlgHash hashAlg, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth auth = Tpm2bAuth.CreateFromPassword(sequencePassword, pool);

        return new HmacStartInput(handle, auth, hashAlg);
    }

    /// <summary>
    /// Initializes the input over an already-rented authorization carrier, adopting its ownership.
    /// </summary>
    /// <param name="handle">The handle of the loaded HMAC key.</param>
    /// <param name="auth">The owned authorization carrier.</param>
    /// <param name="hashAlg">The hash algorithm to use for the HMAC.</param>
    private HmacStartInput(TpmiDhObject handle, Tpm2bAuth auth, TpmiAlgHash hashAlg)
    {
        Handle = handle;
        Auth = auth;
        HashAlg = hashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +         //@handle (TPMI_DH_OBJECT).
               Auth.SerializedSize +  //auth (TPM2B_AUTH).
               sizeof(ushort);        //hashAlg (TPMI_ALG_HASH+).
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
    private string DebuggerDisplay => $"HmacStartInput(Handle=0x{Handle.Value:X8}, HashAlg={HashAlg.Value}, Auth={Auth.Length} bytes)";
}
