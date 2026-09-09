using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_VerifySequenceStart command (CC = TPM_CC_VerifySequenceStart, 0x000001A9).
/// </summary>
/// <remarks>
/// <para>
/// Opens a verification sequence context bound to the key referenced by <see cref="KeyHandle"/>: subsequent
/// TPM2_SequenceUpdate() calls extend the message, and TPM2_VerifySequenceComplete() checks a supplied
/// signature against the accumulated message rather than a digest (TPM 2.0 Library Part 3, clause 17.6). "If
/// keyHandle does not refer to a signing key, the TPM shall return TPM_RC_KEY." "If keyHandle refers to a key
/// whose scheme is TPM_ALG_NULL, the TPM shall return TPM_RC_SCHEME." Here <c>keyHandle</c> names "the handle
/// of a verification key" rather than a signing key, but the same two normative sentences govern it.
/// </para>
/// <para>
/// <c>keyHandle</c> carries Auth Index None: this is a public-key operation, so no authorization accompanies
/// it and the executor frames TPM_ST_NO_SESSIONS when no session accompanies this input; the in-house
/// simulator admits a TPM_ST_SESSIONS frame carrying an audit-only or a decrypt companion over the same
/// no-authorization session admission every other companion-bearing command shares (TPM 2.0 Library Part 3,
/// clause 5.5), the decrypt claim protecting <c>auth</c>, matching <see cref="SignSequenceStartInput"/>'s
/// posture for its own no-authorization handle.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 17.6, Table 89):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT, Auth Index None): the handle of a verification key. Requires no authorization.</description></item>
///   <item><description>auth (TPM2B_AUTH): the authorization value for subsequent use of the sequence.</description></item>
///   <item><description>hint (TPM2B_SIGNATURE_HINT): "hint must be supplied for TPM_ALG_EDDSA, and must be zero-length in all other cases" — empty for every scheme this library executes (ECDSA, RSASSA, RSAPSS).</description></item>
///   <item><description>context (TPM2B_SIGNATURE_CTX): the scheme's additional context — empty for ECDSA, RSASSA, and RSAPSS (Table 220's <c>empty[0]</c> arm).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class VerifySequenceStartInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already released <see cref="SequenceAuth"/>.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_VerifySequenceStart;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>auth</c> (<c>TPM2B_AUTH</c>) is the first entry of the parameter area and carries an explicit size
    /// field (TPM 2.0 Library Part 3, clause 17.6, Table 89), which is what TPM 2.0 Library Part 1, clause
    /// 18.1 requires of an encryptable parameter and what clause 15.4 restates ("for a command or response
    /// parameter to be encrypted, it must be the first parameter and it must be a TPM2B type"). A session
    /// without the <c>decrypt</c> attribute is unaffected.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>keyHandle</c> carries Auth Index None (TPM 2.0 Library Part 3, clause 17.6, Table 89) — the first
    /// session in an authorization area over this command is a companion, never an authorizer, so a decrypt or
    /// encrypt session's own <c>nonceTPM</c> never folds into session 0's command HMAC (TPM 2.0 Library Part 1,
    /// clause 16.6.5).
    /// </remarks>
    public bool IsFirstHandleAuthorized => false;

    /// <summary>
    /// Gets the handle of the verification key that will complete the sequence.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Gets the authorization value for subsequent use of the sequence (TPM2_SequenceUpdate() and
    /// TPM2_VerifySequenceComplete()). Owned pinned storage: released by <see cref="Dispose"/>.
    /// </summary>
    public Tpm2bAuth SequenceAuth { get; }

    /// <summary>
    /// Gets the scheme's hint value. Fixed to <see cref="Tpm2bSignatureHint.Empty"/> — the only conformant
    /// value for every scheme this library executes (ECDSA, RSASSA, RSAPSS; clause 17.6's zero-length rule).
    /// </summary>
    public Tpm2bSignatureHint Hint { get; } = Tpm2bSignatureHint.Empty;

    /// <summary>
    /// Gets the scheme's additional context. Fixed to <see cref="Tpm2bSignatureCtx.Empty"/> — the only
    /// conformant value for every scheme this library executes (ECDSA, RSASSA, RSAPSS; Table 220's
    /// <c>empty[0]</c> arm).
    /// </summary>
    public Tpm2bSignatureCtx Context { get; } = Tpm2bSignatureCtx.Empty;

    /// <summary>
    /// Creates a TPM2_VerifySequenceStart input from raw authorization bytes.
    /// </summary>
    /// <param name="keyHandle">The handle of the verification key that will complete the sequence.</param>
    /// <param name="sequenceAuth">The authorization value for subsequent use of the sequence.</param>
    /// <param name="pool">The memory pool for the authorization buffer.</param>
    /// <returns>A new <see cref="VerifySequenceStartInput"/>.</returns>
    public static VerifySequenceStartInput Create(TpmiDhObject keyHandle, ReadOnlySpan<byte> sequenceAuth, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth auth = Tpm2bAuth.Create(sequenceAuth, pool);

        return new VerifySequenceStartInput(keyHandle, auth);
    }

    /// <summary>
    /// Creates a TPM2_VerifySequenceStart input from a password string, delegating to
    /// <see cref="Tpm2bAuth.CreateFromPassword"/> for the trailing-zero trim TPM 2.0 Library Part 1, clause
    /// 16.6.4.3 describes.
    /// </summary>
    /// <param name="keyHandle">The handle of the verification key that will complete the sequence.</param>
    /// <param name="sequencePassword">The password to use as the sequence's authorization value.</param>
    /// <param name="pool">The memory pool for the authorization buffer.</param>
    /// <returns>A new <see cref="VerifySequenceStartInput"/>.</returns>
    public static VerifySequenceStartInput CreateFromPassword(TpmiDhObject keyHandle, string sequencePassword, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bAuth auth = Tpm2bAuth.CreateFromPassword(sequencePassword, pool);

        return new VerifySequenceStartInput(keyHandle, auth);
    }

    /// <summary>
    /// Initializes a new instance with the specified key handle and sequence authorization value.
    /// </summary>
    /// <param name="keyHandle">The handle of the verification key that will complete the sequence.</param>
    /// <param name="sequenceAuth">The authorization value for subsequent use of the sequence.</param>
    private VerifySequenceStartInput(TpmiDhObject keyHandle, Tpm2bAuth sequenceAuth)
    {
        KeyHandle = keyHandle;
        SequenceAuth = sequenceAuth;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +               //keyHandle (TPMI_DH_OBJECT).
               SequenceAuth.SerializedSize + //auth (TPM2B_AUTH).
               Hint.SerializedSize +         //hint (TPM2B_SIGNATURE_HINT).
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
        Hint.WriteTo(ref writer);
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
    private string DebuggerDisplay => $"VerifySequenceStartInput(Key={KeyHandle}, SequenceAuth={SequenceAuth.Length} bytes)";
}
