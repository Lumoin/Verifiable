using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Sign command (CC = 0x0000015D).
/// </summary>
/// <remarks>
/// <para>
/// Signs a digest with a loaded signing key using the ECDSA scheme. The signing
/// key must have the <c>sign</c> attribute set.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 20.2):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT): Handle of the signing key. Requires authorization.</description></item>
///   <item><description>digest (TPM2B_DIGEST): The digest to sign. Must match the scheme's hash algorithm size.</description></item>
///   <item><description>inScheme (TPMT_SIG_SCHEME): The signing scheme (algorithm + hash algorithm).</description></item>
///   <item><description>validation (TPMT_TK_HASHCHECK): Proof that the digest was created by the TPM. Use a NULL ticket when the digest was computed externally.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SignInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> DigestOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Sign;

    /// <summary>
    /// Gets the handle of the signing key.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Gets the digest to sign.
    /// </summary>
    public ReadOnlyMemory<byte> Digest { get; }

    /// <summary>
    /// Gets the hash algorithm for the ECDSA signing scheme.
    /// </summary>
    public TpmAlgIdConstants SchemeHashAlg { get; }

    /// <summary>
    /// Creates a TPM2_Sign input for ECDSA signing.
    /// </summary>
    /// <remarks>
    /// Configures the command with a NULL validation ticket, which is required when
    /// the digest was computed outside the TPM (TPM 2.0 Part 2, Section 10.7.3).
    /// </remarks>
    /// <param name="keyHandle">The handle of the ECDSA signing key.</param>
    /// <param name="digest">The pre-computed digest bytes to sign.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the ECDSA scheme.</param>
    /// <param name="pool">The memory pool for digest buffer allocation.</param>
    /// <returns>A new <see cref="SignInput"/>.</returns>
    public static SignInput ForEcdsa(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> digest,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> owner = pool.Rent(digest.Length);
        digest.CopyTo(owner.Memory.Span);
        return new SignInput(keyHandle, owner, owner.Memory.Slice(0, digest.Length), schemeHashAlg);
    }

    private SignInput(
        TpmiDhObject keyHandle,
        IMemoryOwner<byte> digestOwner,
        ReadOnlyMemory<byte> digest,
        TpmAlgIdConstants schemeHashAlg)
    {
        KeyHandle = keyHandle;
        DigestOwner = digestOwner;
        Digest = digest;
        SchemeHashAlg = schemeHashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //TPMT_SIG_SCHEME: sigAlg (UINT16) + hashAlg (UINT16).
        const int TpmtSigSchemeSize = sizeof(ushort) + sizeof(ushort);

        //TPMT_TK_HASHCHECK: tag (UINT16) + hierarchy (UINT32) + TPM2B_DIGEST size (UINT16, = 0 for NULL ticket).
        const int TpmtTkHashcheckNullSize = sizeof(ushort) + sizeof(uint) + sizeof(ushort);

        return sizeof(uint) +                               //keyHandle (TPMI_DH_OBJECT)
               sizeof(ushort) + Digest.Length +             //TPM2B_DIGEST: size prefix + bytes
               TpmtSigSchemeSize +
               TpmtTkHashcheckNullSize;
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        KeyHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Digest.Length);
        writer.WriteBytes(Digest.Span);
        writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_ECDSA);
        writer.WriteUInt16((ushort)SchemeHashAlg);

        //NULL ticket: tag = TPM_ST_HASHCHECK, hierarchy = TPM_RH_NULL, digest size = 0.
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_HASHCHECK);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_NULL);
        writer.WriteUInt16(0);
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

    private string DebuggerDisplay => $"SignInput(Key={KeyHandle}, Digest={Digest.Length} bytes, Hash={SchemeHashAlg})";
}