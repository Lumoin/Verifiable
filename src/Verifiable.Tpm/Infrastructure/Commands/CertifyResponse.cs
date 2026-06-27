using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Certify command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 18.2):
/// </para>
/// <list type="bullet">
///   <item><description>certifyInfo (TPM2B_ATTEST): the signed attestation (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_CERTIFY). The signature is over its raw bytes.</description></item>
///   <item><description>signature (TPMT_SIGNATURE): sigAlg (TPMI_ALG_SIG_SCHEME, 2 bytes) selecting a <see cref="TpmuSignature"/> member.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CertifyResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the signed attestation. Verify the signature over <see cref="Tpm2bAttest.GetRawBytes"/>.
    /// </summary>
    public Tpm2bAttest CertifyInfo { get; }

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

    private CertifyResponse(Tpm2bAttest certifyInfo, TpmAlgIdConstants signatureAlgorithm, TpmuSignature signature)
    {
        CertifyInfo = certifyInfo;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
    }

    /// <summary>
    /// Parses a TPM2_Certify response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed certify response.</returns>
    public static CertifyResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bAttest certifyInfo = Tpm2bAttest.Parse(ref reader, pool);
        var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        TpmuSignature signature = TpmuSignature.Parse(sigAlg, ref reader, pool);

        return new CertifyResponse(certifyInfo, sigAlg, signature);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            CertifyInfo.Dispose();
            Signature.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"CertifyResponse({CertifyInfo}, {SignatureAlgorithm}, {Signature})";
}
