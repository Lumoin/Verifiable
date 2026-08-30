using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_SignSequenceStart command (CC = TPM_CC_SignSequenceStart, 0x000001AA).
/// </summary>
/// <remarks>
/// <para>
/// Opens a signing sequence context bound to the key referenced by <see cref="KeyHandle"/>: subsequent
/// TPM2_SequenceUpdate() calls extend the message, and TPM2_SignSequenceComplete() hashes the accumulated
/// message "as required by the key's scheme" and signs it (TPM 2.0 Library Part 3, clause 17.5). "If
/// keyHandle does not refer to a signing key, the TPM shall return TPM_RC_KEY." "If keyHandle refers to a
/// key whose scheme is TPM_ALG_NULL, the TPM shall return TPM_RC_SCHEME."
/// </para>
/// <para>
/// "Authorization of the key referenced by keyHandle is not required at this time. It is checked later,
/// when TPM2_SignSequenceComplete() is called." (clause 17.5), so <see cref="KeyHandle"/> carries no
/// authorization role here and the executor frames TPM_ST_NO_SESSIONS when no session accompanies this
/// input; the in-house simulator refuses a TPM_ST_SESSIONS frame with TPM_RC_BAD_TAG (a recorded
/// limitation), matching <see cref="VerifyDigestSignatureInput"/>'s posture for its own no-authorization
/// handle.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 17.5, Table 87):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT, Auth Index None): the signing key that will complete the sequence. Requires no authorization at Start.</description></item>
///   <item><description>auth (TPM2B_AUTH): the authorization value for subsequent use of the sequence.</description></item>
///   <item><description>context (TPM2B_SIGNATURE_CTX): the scheme's additional context — empty for ECDSA, RSASSA, and RSAPSS (Table 220's <c>empty[0]</c> arm).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SignSequenceStartInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SignSequenceStart;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>auth</c> (<c>TPM2B_AUTH</c>) is the first entry of the parameter area and carries an explicit size
    /// field (TPM 2.0 Library Part 3, clause 17.5, Table 87), which is what TPM 2.0 Library Part 1, clause
    /// 18.1 requires of an encryptable parameter and what clause 15.4 restates ("for a command or response
    /// parameter to be encrypted, it must be the first parameter and it must be a TPM2B type"). A session
    /// without the <c>decrypt</c> attribute is unaffected.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// Gets the handle of the signing key that will complete the sequence.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Gets the authorization value for subsequent use of the sequence (TPM2_SequenceUpdate() and
    /// TPM2_SignSequenceComplete()). Owned pinned storage: released by <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bAuth SequenceAuth { get; }

    /// <summary>
    /// Gets the scheme's additional context. Fixed to <see cref="Tpm2bSignatureCtx.Empty"/> — the only
    /// conformant value for every scheme this library executes (ECDSA, RSASSA, RSAPSS; Table 220's
    /// <c>empty[0]</c> arm).
    /// </summary>
    public Tpm2bSignatureCtx Context { get; } = Tpm2bSignatureCtx.Empty;

    /// <summary>
    /// Creates a TPM2_SignSequenceStart input from raw authorization bytes.
    /// </summary>
    /// <param name="keyHandle">The handle of the signing key that will complete the sequence.</param>
    /// <param name="sequenceAuth">The authorization value for subsequent use of the sequence.</param>
    /// <param name="pool">The memory pool for the authorization buffer.</param>
    /// <returns>A new <see cref="SignSequenceStartInput"/>.</returns>
    public static SignSequenceStartInput Create(TpmiDhObject keyHandle, ReadOnlySpan<byte> sequenceAuth, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth auth = Tpm2bAuth.Create(sequenceAuth, pool);

        return new SignSequenceStartInput(keyHandle, auth);
    }

    /// <summary>
    /// Creates a TPM2_SignSequenceStart input from a password string, delegating to
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> for the trailing-zero trim TPM 2.0 Library Part 1, clause
    /// 16.6.4.3 describes.
    /// </summary>
    /// <param name="keyHandle">The handle of the signing key that will complete the sequence.</param>
    /// <param name="sequencePassword">The password to use as the sequence's authorization value.</param>
    /// <param name="pool">The memory pool for the authorization buffer.</param>
    /// <returns>A new <see cref="SignSequenceStartInput"/>.</returns>
    public static SignSequenceStartInput CreateFromPassword(TpmiDhObject keyHandle, string sequencePassword, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth auth = Tpm2bAuth.CreateFromPassword(sequencePassword, pool);

        return new SignSequenceStartInput(keyHandle, auth);
    }

    private SignSequenceStartInput(TpmiDhObject keyHandle, Tpm2bAuth sequenceAuth)
    {
        KeyHandle = keyHandle;
        SequenceAuth = sequenceAuth;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +               //keyHandle (TPMI_DH_OBJECT).
               SequenceAuth.SerializedSize + //auth (TPM2B_AUTH).
               Context.SerializedSize;       //context (TPM2B_SIGNATURE_CTX).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        KeyHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        SequenceAuth.WriteTo(ref writer);
        Context.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            SequenceAuth.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the key handle and the sequence auth's octet count, never its octets.</summary>
    private string DebuggerDisplay => $"SignSequenceStartInput(Key={KeyHandle}, SequenceAuth={SequenceAuth.Length} bytes)";
}
