using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// An algorithm-agile signature (TPMT_SIGNATURE): the signing-algorithm selector followed by the
/// <see cref="TpmuSignature"/> member it selects.
/// </summary>
/// <remarks>
/// <para>
/// The attestation commands (<c>TPM2_Certify()</c>, <c>TPM2_CertifyCreation()</c>, <c>TPM2_Quote()</c>,
/// <c>TPM2_GetTime()</c>, <c>TPM2_NV_Certify()</c>) and <c>TPM2_Sign()</c> return their signature in this
/// structure, and <c>TPM2_VerifySignature()</c> and <c>TPM2_PolicySigned()</c> take it as input.
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
/// The NULL signature (<c>sigAlg</c> of <c>TPM_ALG_NULL</c>, which selects no member) is not modelled:
/// <see cref="Parse"/> and <see cref="Create"/> refuse it through <see cref="TpmuSignature"/>'s selector check.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.3.4, Table 208.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtSignature: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the signing-algorithm selector (<c>TPM_ALG_ECDSA</c>, <c>TPM_ALG_RSASSA</c>, or <c>TPM_ALG_RSAPSS</c>).
    /// </summary>
    public TpmAlgIdConstants SigAlg { get; }

    /// <summary>
    /// Gets the selected signature member, carrying the hash algorithm and the signature value.
    /// </summary>
    public TpmuSignature Signature { get; }

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
    /// <param name="sigAlg">The signing-algorithm selector.</param>
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
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Signature.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMT_SIGNATURE({SigAlg}, {Signature.HashAlgorithm})";
}
