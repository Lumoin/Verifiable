using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_SignDigest command (CC = 0x000001A6).
/// </summary>
/// <remarks>
/// <para>
/// Signs a digest with a loaded signing key. Unlike TPM2_Sign(), there is no <c>inScheme</c> parameter — the
/// key's own scheme always applies (TPM 2.0 Library Part 3, clause 20.7: "is like TPM2_SignSequenceComplete()",
/// which itself carries no scheme override). The scheme of <see cref="KeyHandle"/> must be a signing scheme that
/// supports signing a digest (e.g. TPM_ALG_ECDSA, but not TPM_ALG_HMAC), and <see cref="Digest"/> must match the
/// size of that scheme's hash algorithm.
/// </para>
/// <para>
/// Signing using a restricted key is permitted, but it requires a valid <see cref="Validation"/> ticket
/// (TPMT_TK_HASHCHECK) proving <see cref="Digest"/> is known by the TPM to be the hash of some message which does
/// not begin with TCG_GENERATED_VALUE. If <see cref="KeyHandle"/> is not a restricted signing key, then
/// <see cref="Validation"/> may be a NULL Ticket with tag TPM_ST_HASHCHECK — <see cref="Create"/> frames one by
/// default; <see cref="CreateForRestrictedKey"/> takes a caller-supplied ticket for the restricted-key path (TPM
/// 2.0 Library Part 3, clause 20.7, Table 126's note).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 20.7, Table 126):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT, Auth Index 1, Auth Role USER): Handle of the signing key. Requires authorization.</description></item>
///   <item><description>context (TPM2B_SIGNATURE_CTX): The scheme's additional context — empty for ECDSA, RSASSA, and RSAPSS (Table 220's <c>empty[0]</c> arm).</description></item>
///   <item><description>digest (TPM2B_DIGEST): The digest to sign. Must match the scheme's hash algorithm size.</description></item>
///   <item><description>validation (TPMT_TK_HASHCHECK): Proof that the digest was created by the TPM, or a NULL ticket for an unrestricted key.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SignDigestInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> DigestOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_SignDigest;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>context</c> (<c>TPM2B_SIGNATURE_CTX</c>) is the first entry of the parameter area and carries an
    /// explicit size field (TPM 2.0 Library Part 3, clause 20.7, Table 126), which is what TPM 2.0 Library Part 1,
    /// clause 18.1 requires of an encryptable parameter and what clause 15.4 restates ("for a command or response
    /// parameter to be encrypted, it must be the first parameter and it must be a TPM2B type"). A session without
    /// the <c>decrypt</c> attribute is unaffected.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// Gets the handle of the signing key.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Gets the scheme's additional context. Fixed to <see cref="Tpm2bSignatureCtx.Empty"/> — the only conformant
    /// value for every scheme this library executes (ECDSA, RSASSA, RSAPSS; Table 220's <c>empty[0]</c> arm).
    /// </summary>
    public Tpm2bSignatureCtx Context { get; } = Tpm2bSignatureCtx.Empty;

    /// <summary>
    /// Gets the digest to sign.
    /// </summary>
    public ReadOnlyMemory<byte> Digest { get; }

    /// <summary>
    /// Gets the hash-check ticket proving the digest was produced by the TPM, or a NULL ticket for an unrestricted
    /// signing key. Not owned by this instance: the caller retains ownership and must keep it alive until this
    /// input has been sent, matching the convention <see cref="CertifyCreationInput.CreationTicket"/> uses for its
    /// caller-supplied ticket. The shared <see cref="TpmtTkHashcheck.Null"/> instance carries no pooled storage, so
    /// ownership is moot for the unrestricted-key path.
    /// </summary>
    public TpmtTkHashcheck Validation { get; }

    /// <summary>
    /// Creates a TPM2_SignDigest input for an unrestricted signing key, framing a NULL <see cref="Validation"/>
    /// ticket (TPM 2.0 Library Part 3, clause 20.7, Table 126's note: "If keyHandle is not a restricted signing
    /// key, then this may be a NULL Ticket with tag = TPM_ST_HASHCHECK").
    /// </summary>
    /// <param name="keyHandle">The handle of the signing key.</param>
    /// <param name="digest">The pre-computed digest bytes to sign.</param>
    /// <param name="pool">The memory pool for digest buffer allocation.</param>
    /// <returns>A new <see cref="SignDigestInput"/>.</returns>
    public static SignDigestInput Create(TpmiDhObject keyHandle, ReadOnlySpan<byte> digest, BaseMemoryPool pool)
    {
        return CreateForRestrictedKey(keyHandle, digest, TpmtTkHashcheck.Null, pool);
    }

    /// <summary>
    /// Creates a TPM2_SignDigest input carrying a caller-supplied <see cref="Validation"/> ticket, as required
    /// when <paramref name="keyHandle"/> is a restricted signing key (TPM 2.0 Library Part 3, clause 20.7, Table
    /// 126's note).
    /// </summary>
    /// <param name="keyHandle">The handle of the signing key.</param>
    /// <param name="digest">The pre-computed digest bytes to sign.</param>
    /// <param name="validation">The hash-check ticket proving the digest was produced by the TPM. Not owned by the returned input.</param>
    /// <param name="pool">The memory pool for digest buffer allocation.</param>
    /// <returns>A new <see cref="SignDigestInput"/>.</returns>
    public static SignDigestInput CreateForRestrictedKey(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> digest,
        TpmtTkHashcheck validation,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(validation);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(digest.Length);
        digest.CopyTo(owner.Memory.Span);

        return new SignDigestInput(keyHandle, owner, owner.Memory.Slice(0, digest.Length), validation);
    }

    private SignDigestInput(
        TpmiDhObject keyHandle,
        IMemoryOwner<byte> digestOwner,
        ReadOnlyMemory<byte> digest,
        TpmtTkHashcheck validation)
    {
        KeyHandle = keyHandle;
        DigestOwner = digestOwner;
        Digest = digest;
        Validation = validation;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +                     //keyHandle (TPMI_DH_OBJECT).
               Context.SerializedSize +            //context (TPM2B_SIGNATURE_CTX).
               sizeof(ushort) + Digest.Length +    //digest (TPM2B_DIGEST): size prefix + bytes.
               Validation.SerializedSize;          //validation (TPMT_TK_HASHCHECK).
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

        Context.WriteTo(ref writer);
        writer.WriteUInt16((ushort)Digest.Length);
        writer.WriteBytes(Digest.Span);
        Validation.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            DigestOwner.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the key handle and the digest's and context's octet counts, never their octets.</summary>
    private string DebuggerDisplay => $"SignDigestInput(Key={KeyHandle}, Digest={Digest.Length} bytes, Context={Context.Size} bytes)";
}
