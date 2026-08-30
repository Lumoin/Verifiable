using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_VerifySignature command (CC = 0x00000177).
/// </summary>
/// <remarks>
/// <para>
/// Validates that <see cref="Signature"/> is a valid signature over <see cref="Digest"/> made with the key
/// referenced by <see cref="KeyHandle"/>. <see cref="KeyHandle"/> requires no authorization at all, so the
/// command carries no authorization area at all (TPM_ST_NO_SESSIONS): for an asymmetric key only the public
/// portion is consulted, while for a KEYEDHASH HMAC key "both the public and private portions need to be
/// loaded" — the TPM recomputes the HMAC under the key's sensitive bits (TPM 2.0 Library Part 3, clause 20.2.1).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 20.2, Table 116):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT): The key that verifies the signature. Requires no authorization.</description></item>
///   <item><description>digest (TPM2B_DIGEST): The digest the signature is claimed to be over.</description></item>
///   <item><description>signature (TPMT_SIGNATURE): sigAlg (TPMI_ALG_SIG_SCHEME) selects the ECDSA r/s pair, the single RSA signature buffer, or the HMAC member's unsized TPMT_HA digest (TPM 2.0 Library Part 2, clause 10.2.2, Table 89).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class VerifySignatureInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> DigestOwner { get; }

    private IMemoryOwner<byte> SignatureOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_VerifySignature;

    /// <summary>
    /// Gets the handle of the key whose public part verifies the signature.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

    /// <summary>
    /// Gets the digest the signature is claimed to be over.
    /// </summary>
    public ReadOnlyMemory<byte> Digest { get; }

    /// <summary>
    /// Gets the signing algorithm (TPMI_ALG_SIG_SCHEME): TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, or TPM_ALG_HMAC.
    /// </summary>
    public TpmAlgIdConstants SignatureScheme { get; }

    /// <summary>
    /// Gets the hash algorithm carried inside the signature.
    /// </summary>
    public TpmAlgIdConstants SchemeHashAlg { get; }

    /// <summary>
    /// Gets the signature octets: IEEE P1363 r ‖ s for ECDSA, the raw RSA signature for RSASSA/RSAPSS, or the
    /// raw HMAC digest (the TPMT_HA member's unsized value) for TPM_ALG_HMAC.
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>
    /// Creates a TPM2_VerifySignature input for an ECDSA signature.
    /// </summary>
    /// <param name="keyHandle">The handle of the ECDSA key whose public point verifies the signature.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="signature">The signature as IEEE P1363 r ‖ s.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the digest and signature buffers.</param>
    /// <returns>A new <see cref="VerifySignatureInput"/>.</returns>
    public static VerifySignatureInput ForEcdsa(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(keyHandle, digest, signature, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_VerifySignature input for an RSASSA (RSA PKCS#1 v1.5) signature.
    /// </summary>
    /// <param name="keyHandle">The handle of the RSA key whose public modulus verifies the signature.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="signature">The raw RSA signature octets.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the digest and signature buffers.</param>
    /// <returns>A new <see cref="VerifySignatureInput"/>.</returns>
    public static VerifySignatureInput ForRsaSsa(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(keyHandle, digest, signature, TpmAlgIdConstants.TPM_ALG_RSASSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_VerifySignature input for an RSAPSS signature.
    /// </summary>
    /// <param name="keyHandle">The handle of the RSA key whose public modulus verifies the signature.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="signature">The raw RSA signature octets.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the digest and signature buffers.</param>
    /// <returns>A new <see cref="VerifySignatureInput"/>.</returns>
    public static VerifySignatureInput ForRsaPss(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(keyHandle, digest, signature, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_VerifySignature input for the given signing scheme.
    /// </summary>
    /// <param name="keyHandle">The handle of the key whose public part verifies the signature.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, the raw RSA signature for RSASSA/RSAPSS, or the raw HMAC digest (the TPMT_HA member's unsized value) for TPM_ALG_HMAC.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, or TPM_ALG_HMAC).</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the digest and signature buffers.</param>
    /// <returns>A new <see cref="VerifySignatureInput"/>.</returns>
    public static VerifySignatureInput Create(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> digestOwner = pool.Rent(digest.Length);
        digest.CopyTo(digestOwner.Memory.Span);

        IMemoryOwner<byte> signatureOwner = pool.Rent(signature.Length);
        signature.CopyTo(signatureOwner.Memory.Span);

        return new VerifySignatureInput(
            keyHandle,
            digestOwner,
            digestOwner.Memory.Slice(0, digest.Length),
            signatureOwner,
            signatureOwner.Memory.Slice(0, signature.Length),
            signatureScheme,
            schemeHashAlg);
    }

    private VerifySignatureInput(
        TpmiDhObject keyHandle,
        IMemoryOwner<byte> digestOwner,
        ReadOnlyMemory<byte> digest,
        IMemoryOwner<byte> signatureOwner,
        ReadOnlyMemory<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg)
    {
        KeyHandle = keyHandle;
        DigestOwner = digestOwner;
        Digest = digest;
        SignatureOwner = signatureOwner;
        Signature = signature;
        SignatureScheme = signatureScheme;
        SchemeHashAlg = schemeHashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +                          //keyHandle (TPMI_DH_OBJECT).
               sizeof(ushort) + Digest.Length +         //digest (TPM2B_DIGEST): size prefix + bytes.
               TpmtSignatureFraming.GetSerializedSize(SignatureScheme, Signature.Length); //signature (TPMT_SIGNATURE).
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

        writer.WriteUInt16((ushort)Digest.Length);
        writer.WriteBytes(Digest.Span);

        TpmtSignatureFraming.Write(ref writer, SignatureScheme, SchemeHashAlg, Signature.Span);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            DigestOwner.Dispose();
            SignatureOwner.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"VerifySignatureInput(Key={KeyHandle}, Digest={Digest.Length} bytes, Scheme={SignatureScheme}, Hash={SchemeHashAlg})";
}
