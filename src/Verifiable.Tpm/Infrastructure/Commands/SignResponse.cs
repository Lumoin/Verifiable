using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Sign command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 20.2): a single TPMT_SIGNATURE whose active member
/// is selected by the signing algorithm.
/// </para>
/// <list type="bullet">
///   <item><description>sigAlg (TPMI_ALG_SIG_SCHEME, 2 bytes): the union selector.</description></item>
///   <item><description>signature (TPMU_SIGNATURE): see <see cref="TpmuSignature"/> — TPMS_SIGNATURE_ECDSA (hash + r + s) or TPMS_SIGNATURE_RSA (hash + sig).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class SignResponse: IDisposable, ITpmWireType
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

    private SignResponse(TpmAlgIdConstants signatureAlgorithm, TpmuSignature signature)
    {
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
    }

    /// <summary>
    /// Parses a TPM2_Sign response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed sign response.</returns>
    public static SignResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        TpmuSignature signature = TpmuSignature.Parse(sigAlg, ref reader, pool);

        return new SignResponse(sigAlg, signature);
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

    private string DebuggerDisplay => $"SignResponse({SignatureAlgorithm}, {Signature})";
}
