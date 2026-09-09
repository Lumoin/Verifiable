using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// An algorithm-agile signature (TPMT_SIGNATURE): the signing-algorithm selector followed by the
/// <see cref="TpmuSignature"/> member it selects.
/// </summary>
/// <remarks>
/// <para>
/// The attestation commands (<c>TPM2_Certify()</c>, <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>,
/// <c>TPM2_GetTime()</c>, <c>TPM2_NV_Certify()</c>) return their signature in this structure, and
/// <c>TPM2_VerifyDigestSignature()</c>, <c>TPM2_VerifySequenceComplete()</c>, and <c>TPM2_PolicySigned()</c>
/// take it as input. For the HMAC arm specifically, the producer is <c>TPM2_SignSequenceComplete()</c> — as is
/// <c>TPM2_Sign()</c>, deprecated in version 185 (Part 3, clause 20.1, Table 115's HMAC row) — and the consumers
/// are <c>TPM2_VerifySequenceComplete()</c> and the likewise-deprecated <c>TPM2_VerifySignature()</c> (Part 3,
/// clause 20.2.1); <c>TPM2_SignDigest()</c> and <c>TPM2_VerifyDigestSignature()</c> take no HMAC scheme at all
/// (clause 20.7.1: "e.g., TPM_ALG_ECDSA, but not TPM_ALG_HMAC"; Table 115's HMAC row: "Not supported").
/// <c>TPM2_HMAC()</c> and
/// <c>TPM2_SequenceComplete()</c> return their HMAC result as a <c>TPM2B_DIGEST</c> instead (Part 3, Tables 72
/// and 94), never as this structure; <c>TPM2_HMAC_Start()</c> returns only a sequence handle (Table 81), no
/// digest at all.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_SIG_SCHEME+ sigAlg;             // Selector of the algorithm used to construct the signature.
///     TPMU_SIGNATURE       signature;          // The signature member sigAlg selects.
/// } TPMT_SIGNATURE;
/// </code>
/// <para>
/// Modelled <c>sigAlg</c> arms: <c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, <c>TPM_ALG_RSAPSS</c>,
/// <c>TPM_ALG_HMAC</c> (<see cref="Hmac"/>), and <c>TPM_ALG_NULL</c> (<see cref="Null"/>) — the NULL Signature: "If
/// the handle for the signing key (signHandle) is TPM_RH_NULL, then all of the actions of the command are
/// performed, and the attestation block is 'signed' with the NULL Signature" (TPM 2.0 Library Part 3, clause
/// 18.1). The NULL Signature carries the <c>sigAlg</c> selector alone — <see cref="TpmuSignature"/> selects no
/// member for it — and the reference implementation produces it by leaving the signing step out entirely:
/// <c>SignAttestInfo</c> sets <c>signature-&gt;sigAlg = TPM_ALG_NULL</c> when the signing key is absent, skipping
/// the hash-and-sign step it otherwise runs.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.3.6, Table 219.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtSignature: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the signing-algorithm selector (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, <c>TPM_ALG_RSAPSS</c>,
    /// or <c>TPM_ALG_HMAC</c>).
    /// </summary>
    public TpmAlgIdConstants SigAlg { get; }

    /// <summary>
    /// Gets the selected signature member, carrying the hash algorithm and the signature value.
    /// </summary>
    public TpmuSignature Signature { get; }

    /// <summary>
    /// Gets the HMAC digest, when <see cref="SigAlg"/> is TPM_ALG_HMAC; otherwise <see langword="null"/>.
    /// </summary>
    public ReadOnlyMemory<byte>? HmacDigest => Signature.HmacSignature?.AsReadOnlyMemory();

    /// <summary>
    /// Gets the shared NULL Signature (<c>sigAlg</c> TPM_ALG_NULL, no member) — the signature Part 3, clause 18.1
    /// describes for a signing key referenced as <c>TPM_RH_NULL</c>. Immune to disposal: <see cref="Dispose"/> is
    /// a no-op for this instance, since it owns no buffer, so the shared instance stays usable for every holder.
    /// </summary>
    public static TpmtSignature Null { get; } = new(TpmAlgIdConstants.TPM_ALG_NULL, TpmuSignature.Null);

    /// <summary>
    /// Gets whether this is the NULL Signature (<see cref="SigAlg"/> is TPM_ALG_NULL).
    /// </summary>
    public bool IsNull => SigAlg == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Initializes a new algorithm-agile signature over an already-built member.
    /// </summary>
    /// <param name="sigAlg">The signing-algorithm selector.</param>
    /// <param name="signature">The selected member; ownership transfers to this instance.</param>
    private TpmtSignature(TpmAlgIdConstants sigAlg, TpmuSignature signature)
    {
        SigAlg = sigAlg;
        Signature = signature;
    }

    /// <summary>
    /// Creates an algorithm-agile signature from a raw signature value.
    /// </summary>
    /// <param name="sigAlg">The signing-algorithm selector. <c>TPM_ALG_NULL</c> is admitted: <paramref name="hashAlg"/>
    /// and <paramref name="signature"/> are then ignored and the shared <see cref="Null"/> value is returned.</param>
    /// <param name="hashAlg">The hash algorithm the signature was made with, carried inside the member.</param>
    /// <param name="signature">The raw signature: IEEE P1363 <c>r ‖ s</c> for ECDSA, or the RSA signature octets.</param>
    /// <param name="pool">The memory pool for the member's buffers.</param>
    /// <returns>The created signature; the caller owns and disposes it.</returns>
    /// <exception cref="NotSupportedException"><paramref name="sigAlg"/> is not a supported signing algorithm.</exception>
    /// <exception cref="ArgumentException">An ECDSA <paramref name="signature"/> is not an even-length <c>r ‖ s</c>.</exception>
    public static TpmtSignature Create(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signature, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new TpmtSignature(sigAlg, TpmuSignature.Create(sigAlg, hashAlg, signature, pool));
    }

    /// <summary>
    /// Creates an ECDSA algorithm-agile signature directly from its independently-sized <c>signatureR</c>/
    /// <c>signatureS</c> components, mirroring
    /// <see cref="TpmuSignature.CreateEcdsaFromComponents(TpmAlgIdConstants, ReadOnlySpan{byte}, ReadOnlySpan{byte}, BaseMemoryPool)"/>
    /// for a caller that already holds the two wire-parsed spans separately rather than one concatenated P1363
    /// buffer — a wire parse of <c>TPMS_SIGNATURE_ECC</c> (Part 2, clause 11.3.2, Table 214), where
    /// <c>signatureR</c> and <c>signatureS</c> are unrelated in length.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm the signature was made with, carried inside the member.</param>
    /// <param name="signatureR">The <c>signatureR</c> component.</param>
    /// <param name="signatureS">The <c>signatureS</c> component.</param>
    /// <param name="pool">The memory pool for the member's buffers.</param>
    /// <returns>The created signature; the caller owns and disposes it.</returns>
    public static TpmtSignature CreateEcdsaFromComponents(TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signatureR, ReadOnlySpan<byte> signatureS, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new TpmtSignature(TpmAlgIdConstants.TPM_ALG_ECDSA, TpmuSignature.CreateEcdsaFromComponents(hashAlg, signatureR, signatureS, pool));
    }

    /// <summary>
    /// Creates an algorithm-agile HMAC signature (<c>sigAlg</c> TPM_ALG_HMAC): the member is a self-contained
    /// TPMT_HA (<paramref name="hashAlg"/> plus <paramref name="digest"/>), the shape <c>TPM2_SignSequenceComplete()</c>
    /// produces for an HMAC key (as does <c>TPM2_Sign()</c>, deprecated in version 185; <c>TPM2_SignDigest()</c>
    /// is "Not supported" for HMAC, Part 3, clause 20.1, Table 115) — never <c>TPM2_HMAC()</c> or
    /// <c>TPM2_SequenceComplete()</c>, whose HMAC result is a <c>TPM2B_DIGEST</c> instead.
    /// </summary>
    /// <param name="hashAlg">The HMAC hash algorithm.</param>
    /// <param name="digest">The HMAC digest; must be exactly <paramref name="hashAlg"/>'s digest size.</param>
    /// <param name="pool">The memory pool for the member's buffer.</param>
    /// <returns>The created signature; the caller owns and disposes it.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="digest"/> does not match <paramref name="hashAlg"/>'s digest size, or
    /// <paramref name="hashAlg"/> is <c>TPM_ALG_NULL</c> or has no known digest size — a value
    /// <see cref="Parse"/> could never produce for an HMAC member.
    /// </exception>
    public static TpmtSignature Hmac(TpmiAlgHash hashAlg, ReadOnlySpan<byte> digest, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new TpmtSignature(TpmAlgIdConstants.TPM_ALG_HMAC, TpmuSignature.Create(TpmAlgIdConstants.TPM_ALG_HMAC, hashAlg.Value, digest, pool));
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    /// <returns>The number of octets <see cref="WriteTo"/> produces.</returns>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return sizeof(ushort) + Signature.GetSerializedSize();
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)SigAlg);
        Signature.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses an algorithm-agile signature from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at <c>sigAlg</c>.</param>
    /// <param name="pool">The memory pool for the member's buffers.</param>
    /// <returns>The parsed signature.</returns>
    /// <exception cref="NotSupportedException">The selector is not a supported signing algorithm.</exception>
    public static TpmtSignature Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        return new TpmtSignature(sigAlg, TpmuSignature.Parse(sigAlg, ref reader, pool));
    }

    /// <summary>
    /// Releases the memory owned by this structure. A no-op when <see cref="IsNull"/>, since the NULL Signature
    /// owns no buffer — this keeps the shared <see cref="Null"/> instance usable for every holder regardless of
    /// how many dispose it.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && !IsNull)
        {
            Signature.Dispose();
            disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => IsNull ? "TPMT_SIGNATURE(NULL)" : $"TPMT_SIGNATURE({SigAlg}, {Signature.HashAlgorithm})";
}
