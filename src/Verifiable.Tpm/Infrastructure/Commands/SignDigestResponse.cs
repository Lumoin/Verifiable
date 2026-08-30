using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_SignDigest command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 20.7, Table 127): a single TPMT_SIGNATURE whose active
/// member is selected by the signing algorithm — the same wire shape <see cref="SignResponse"/> parses for
/// TPM2_Sign(), modeled as a distinct type here because it answers a distinct command.
/// </para>
/// <list type="bullet">
///   <item><description>sigAlg (TPMI_ALG_SIG_SCHEME, 2 bytes): the union selector.</description></item>
///   <item><description>signature (TPMU_SIGNATURE): see <see cref="TpmuSignature"/> — TPMS_SIGNATURE_ECDSA (hash + r + s) or TPMS_SIGNATURE_RSA (hash + sig).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SignDigestResponse: IDisposable, ITpmWireType
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

    private SignDigestResponse(TpmAlgIdConstants signatureAlgorithm, TpmuSignature signature)
    {
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
    }

    /// <summary>
    /// Parses a TPM2_SignDigest response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed sign-digest response.</returns>
    public static SignDigestResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        TpmuSignature signature = TpmuSignature.Parse(sigAlg, ref reader, pool);

        return new SignDigestResponse(sigAlg, signature);
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
    private string DebuggerDisplay => $"SignDigestResponse({SignatureAlgorithm}, {Signature})";
}
