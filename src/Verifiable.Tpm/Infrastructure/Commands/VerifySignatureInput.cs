using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_VerifySignature command (CC = 0x00000177).
/// </summary>
/// <remarks>
/// <para>
/// Validates that <see cref="Signature"/> is a valid signature over <see cref="Digest"/> made with the key
/// referenced by <see cref="KeyHandle"/>. This is a public-key operation: <see cref="KeyHandle"/> requires no
/// authorization at all, so the command carries no authorization area at all (TPM_ST_NO_SESSIONS).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 20.1, Table 104):
/// </para>
/// <list type="bullet">
///   <item><description>keyHandle (TPMI_DH_OBJECT): The key whose public part verifies the signature. Requires no authorization.</description></item>
///   <item><description>digest (TPM2B_DIGEST): The digest the signature is claimed to be over.</description></item>
///   <item><description>signature (TPMT_SIGNATURE): sigAlg (TPMI_ALG_SIG_SCHEME) selects the ECDSA r/s pair or the single RSA signature buffer.</description></item>
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
    /// Gets the signing algorithm (TPMI_ALG_SIG_SCHEME): TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS.
    /// </summary>
    public TpmAlgIdConstants SignatureScheme { get; }

    /// <summary>
    /// Gets the hash algorithm carried inside the signature.
    /// </summary>
    public TpmAlgIdConstants SchemeHashAlg { get; }

    /// <summary>
    /// Gets the signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.
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
        MemoryPool<byte> pool)
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
        MemoryPool<byte> pool)
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
        MemoryPool<byte> pool)
    {
        return Create(keyHandle, digest, signature, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_VerifySignature input for the given signing scheme.
    /// </summary>
    /// <param name="keyHandle">The handle of the key whose public part verifies the signature.</param>
    /// <param name="digest">The digest the signature is claimed to be over.</param>
    /// <param name="signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, or the raw RSA signature for RSASSA/RSAPSS.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the digest and signature buffers.</param>
    /// <returns>A new <see cref="VerifySignatureInput"/>.</returns>
    public static VerifySignatureInput Create(
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> digest,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
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
        //TPMT_SIGNATURE: sigAlg (UINT16) + hash (UINT16) + either the ECDSA r/s TPM2B pair (two size prefixes)
        //or the single RSA TPM2B signature (one size prefix); the signature octets are Signature.Length either way.
        int signatureFramingSize = SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA
            ? (4 * sizeof(ushort))
            : (3 * sizeof(ushort));

        return sizeof(uint) +                          //keyHandle (TPMI_DH_OBJECT).
               sizeof(ushort) + Digest.Length +         //digest (TPM2B_DIGEST): size prefix + bytes.
               signatureFramingSize + Signature.Length; //signature (TPMT_SIGNATURE).
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

        writer.WriteUInt16((ushort)SignatureScheme);  //sigAlg: the TPMU_SIGNATURE selector.
        writer.WriteUInt16((ushort)SchemeHashAlg);    //hash inside the signature member.

        ReadOnlySpan<byte> signatureBytes = Signature.Span;
        if(SignatureScheme == TpmAlgIdConstants.TPM_ALG_ECDSA)
        {
            //TPMS_SIGNATURE_ECDSA: r and s are the equal-width halves of the IEEE P1363 signature — the same
            //framing the simulator's response serializer uses for TPM2_Sign()/TPM2_Certify() and the other
            //attest-producing commands.
            if((signatureBytes.Length & 1) != 0)
            {
                throw new InvalidOperationException(
                    $"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {signatureBytes.Length} octets.");
            }

            int fieldWidth = signatureBytes.Length / 2;
            writer.WriteTpm2b(signatureBytes[..fieldWidth]);   //signatureR (TPM2B_ECC_PARAMETER).
            writer.WriteTpm2b(signatureBytes[fieldWidth..]);   //signatureS (TPM2B_ECC_PARAMETER).
        }
        else
        {
            //TPMS_SIGNATURE_RSA: the whole signature as one TPM2B_PUBLIC_KEY_RSA.
            writer.WriteTpm2b(signatureBytes);
        }
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
