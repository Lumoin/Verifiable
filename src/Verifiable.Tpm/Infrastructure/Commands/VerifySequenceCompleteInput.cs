using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_VerifySequenceComplete command (CC = TPM_CC_VerifySequenceComplete, 0x000001A3).
/// </summary>
/// <remarks>
/// <para>
/// Checks <see cref="Signature"/> against the message accumulated by the sequence referenced by
/// <see cref="SequenceHandle"/>, using the key referenced by <see cref="KeyHandle"/> — "Is
/// like TPM2_VerifySignature()" (TPM 2.0 Library Part 3, clause 20.3) with one difference: "Verifying takes a
/// message (provided via TPM2_SequenceUpdate()) rather than a digest." "If keyHandle refers to a key that is
/// not the same as the key that was used to start the signature context, the TPM shall return
/// TPM_RC_SIGN_CONTEXT_KEY." "If the signature check succeeds, then the TPM will produce a TPMT_TK_VERIFIED.
/// Otherwise, the TPM shall return TPM_RC_SIGNATURE." "If the key is in the NULL hierarchy, then hmac in the
/// ticket will be the Empty Buffer." "If keyHandle references an asymmetric key, only the public portion of
/// the key needs to be loaded. If keyHandle references a symmetric key, both the public and private portions
/// need to be loaded" (clause 20.3.1) — either way <c>keyHandle</c> requires no authorization (Table 118, Auth
/// Index None). Success flushes the sequence context ({F}, TPM 2.0 Library Part 1, clause 29.4.6).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 20.3, Table 118):
/// </para>
/// <list type="bullet">
///   <item><description>sequenceHandle (TPMI_DH_OBJECT, Auth Index 1, Auth Role USER): the verification sequence to complete and consume. Requires the sequence's authorization value.</description></item>
///   <item><description>keyHandle (TPMI_DH_OBJECT, Auth Index None): the handle of a verification key. Requires no authorization.</description></item>
///   <item><description>signature (TPMT_SIGNATURE): sigAlg (TPMI_ALG_SIG_SCHEME) selects the ECDSA r/s pair, the single RSA signature buffer, or the HMAC member's unsized TPMT_HA digest (TPM 2.0 Library Part 2, clause 10.2.2, Table 89).</description></item>
/// </list>
/// <para>
/// The two handles' Auth Index order (sequence first, key second) fixes the order a caller passes sessions
/// to the executor: the session at index 0 authorizes <see cref="SequenceHandle"/>; <see cref="KeyHandle"/>
/// takes no session at all.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class VerifySequenceCompleteInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already released <see cref="SignatureOwner"/>.</summary>
    private bool Disposed { get; set; }

    /// <summary>The pooled rental backing <see cref="Signature"/>; <see cref="Dispose"/> releases it.</summary>
    private IMemoryOwner<byte> SignatureOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_VerifySequenceComplete;

    /// <inheritdoc/>
    /// <remarks>
    /// The parameter area's only entry is <c>signature</c> (TPMT_SIGNATURE), which carries no leading TPM2B
    /// size field of its own (TPM 2.0 Library Part 3, clause 20.3, Table 118). TPM 2.0 Library Part 1,
    /// clause 15.4 requires the first parameter to be a TPM2B type for session-based parameter encryption
    /// to apply, so this parameter is not eligible.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => false;

    /// <summary>
    /// The sequence handle sits at position 0 of the handle area (TPM 2.0 Library Part 3, clause 20.3, Table 118: <c>@sequenceHandle</c> first, <c>keyHandle</c> second), so its cpHash Name term is the Empty
    /// Buffer the executor derives (TPM 2.0 Library Part 1, clause 29.4.6).
    /// </summary>
    /// <param name="handleIndex">The zero-based position in the command's handle area.</param>
    /// <returns><see langword="true"/> for the sequence handle's position.</returns>
    public bool HandleIsSequence(int handleIndex) => handleIndex == 0;

    /// <summary>
    /// Gets the handle of the verification sequence to complete and consume.
    /// </summary>
    public TpmiDhObject SequenceHandle { get; }

    /// <summary>
    /// Gets the handle of the verification key.
    /// </summary>
    public TpmiDhObject KeyHandle { get; }

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
    /// Creates a TPM2_VerifySequenceComplete input for an ECDSA signature.
    /// </summary>
    /// <param name="sequenceHandle">The handle of the verification sequence to complete and consume.</param>
    /// <param name="keyHandle">The handle of the ECDSA key whose public point verifies the signature.</param>
    /// <param name="signature">The signature as IEEE P1363 r ‖ s.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the signature buffer.</param>
    /// <returns>A new <see cref="VerifySequenceCompleteInput"/>.</returns>
    public static VerifySequenceCompleteInput ForEcdsa(
        TpmiDhObject sequenceHandle,
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(sequenceHandle, keyHandle, signature, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_VerifySequenceComplete input for an RSASSA (RSA PKCS#1 v1.5) signature.
    /// </summary>
    /// <param name="sequenceHandle">The handle of the verification sequence to complete and consume.</param>
    /// <param name="keyHandle">The handle of the RSA key whose public modulus verifies the signature.</param>
    /// <param name="signature">The raw RSA signature octets.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the signature buffer.</param>
    /// <returns>A new <see cref="VerifySequenceCompleteInput"/>.</returns>
    public static VerifySequenceCompleteInput ForRsaSsa(
        TpmiDhObject sequenceHandle,
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(sequenceHandle, keyHandle, signature, TpmAlgIdConstants.TPM_ALG_RSASSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_VerifySequenceComplete input for an RSAPSS signature.
    /// </summary>
    /// <param name="sequenceHandle">The handle of the verification sequence to complete and consume.</param>
    /// <param name="keyHandle">The handle of the RSA key whose public modulus verifies the signature.</param>
    /// <param name="signature">The raw RSA signature octets.</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the signature buffer.</param>
    /// <returns>A new <see cref="VerifySequenceCompleteInput"/>.</returns>
    public static VerifySequenceCompleteInput ForRsaPss(
        TpmiDhObject sequenceHandle,
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(sequenceHandle, keyHandle, signature, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_VerifySequenceComplete input for the given signing scheme.
    /// </summary>
    /// <param name="sequenceHandle">The handle of the verification sequence to complete and consume.</param>
    /// <param name="keyHandle">The handle of the verification key.</param>
    /// <param name="signature">The signature octets: IEEE P1363 r ‖ s for ECDSA, the raw RSA signature for RSASSA/RSAPSS, or the raw HMAC digest (the TPMT_HA member's unsized value) for TPM_ALG_HMAC.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, or TPM_ALG_HMAC).</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    /// <param name="pool">The memory pool for the signature buffer.</param>
    /// <returns>A new <see cref="VerifySequenceCompleteInput"/>.</returns>
    public static VerifySequenceCompleteInput Create(
        TpmiDhObject sequenceHandle,
        TpmiDhObject keyHandle,
        ReadOnlySpan<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> signatureOwner = pool.Rent(signature.Length);
        signature.CopyTo(signatureOwner.Memory.Span);

        return new VerifySequenceCompleteInput(
            sequenceHandle,
            keyHandle,
            signatureOwner,
            signatureOwner.Memory.Slice(0, signature.Length),
            signatureScheme,
            schemeHashAlg);
    }

    /// <summary>
    /// Initializes a new instance with the specified handles, signature storage, and scheme identifiers.
    /// </summary>
    /// <param name="sequenceHandle">The handle of the verification sequence to complete and consume.</param>
    /// <param name="keyHandle">The handle of the verification key.</param>
    /// <param name="signatureOwner">The pooled rental backing <paramref name="signature"/>.</param>
    /// <param name="signature">The signature octets sliced from <paramref name="signatureOwner"/>.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, or TPM_ALG_HMAC).</param>
    /// <param name="schemeHashAlg">The hash algorithm carried inside the signature.</param>
    private VerifySequenceCompleteInput(
        TpmiDhObject sequenceHandle,
        TpmiDhObject keyHandle,
        IMemoryOwner<byte> signatureOwner,
        ReadOnlyMemory<byte> signature,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg)
    {
        SequenceHandle = sequenceHandle;
        KeyHandle = keyHandle;
        SignatureOwner = signatureOwner;
        Signature = signature;
        SignatureScheme = signatureScheme;
        SchemeHashAlg = schemeHashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +                          //sequenceHandle (TPMI_DH_OBJECT).
               sizeof(uint) +                          //keyHandle (TPMI_DH_OBJECT).
               TpmtSignatureFraming.GetSerializedSize(SignatureScheme, Signature.Length); //signature (TPMT_SIGNATURE).
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

        TpmtSignatureFraming.Write(ref writer, SignatureScheme, SchemeHashAlg, Signature.Span);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            SignatureOwner.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: both handles and the signature scheme and hash, never the signature octets.</summary>
    private string DebuggerDisplay => $"VerifySequenceCompleteInput(Sequence={SequenceHandle}, Key={KeyHandle}, Scheme={SignatureScheme}, Hash={SchemeHashAlg})";
}
