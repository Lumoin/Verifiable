using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_SignSequenceComplete command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 20.6, Table 125): a single TPMT_SIGNATURE whose
/// active member is selected by the signing algorithm — the same wire shape <see cref="SignDigestResponse"/>
/// parses for TPM2_SignDigest(), modeled as a distinct type here because it answers a distinct command. On
/// success the sequence context named by the request's <c>sequenceHandle</c> is flushed from the TPM (TPM
/// 2.0 Library Part 1, clause 29.4.6).
/// </para>
/// <list type="bullet">
///   <item><description>sigAlg (TPMI_ALG_SIG_SCHEME, 2 bytes): the union selector.</description></item>
///   <item><description>signature (TPMU_SIGNATURE): see <see cref="TpmuSignature"/> — TPMS_SIGNATURE_ECDSA (hash + r + s) or TPMS_SIGNATURE_RSA (hash + sig).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SignSequenceCompleteResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the signing algorithm reported by the TPM (the TPMU_SIGNATURE selector).
    /// </summary>
    public TpmAlgIdConstants SignatureAlgorithm { get; }

    /// <summary>
    /// Gets the parsed signature value.
    /// </summary>
    public TpmuSignature Signature { get; }

    /// <summary>
    /// Gets the hash algorithm reported by the TPM inside the signature.
    /// </summary>
    public TpmAlgIdConstants HashAlgorithm => Signature.HashAlgorithm;

    private SignSequenceCompleteResponse(TpmAlgIdConstants signatureAlgorithm, TpmuSignature signature)
    {
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
    }

    /// <summary>
    /// Parses a TPM2_SignSequenceComplete response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed sign-sequence-complete response.</returns>
    public static SignSequenceCompleteResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        TpmuSignature signature = TpmuSignature.Parse(sigAlg, ref reader, pool);

        return new SignSequenceCompleteResponse(sigAlg, signature);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Signature.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger's one-line rendering: the signature algorithm and the parsed signature's own rendering.</summary>
    private string DebuggerDisplay => $"SignSequenceCompleteResponse({SignatureAlgorithm}, {Signature})";
}
