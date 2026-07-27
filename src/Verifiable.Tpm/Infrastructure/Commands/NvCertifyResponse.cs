using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_NV_Certify command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, Section 31.16) — the same TPM2B_ATTEST + TPMT_SIGNATURE shape as
/// TPM2_Certify's and TPM2_Quote's responses. Only the TPMS_NV_CERTIFY_INFO attestation form (TPM_ST_ATTEST_NV)
/// is modelled; the TPMS_NV_DIGEST_CERTIFY_INFO form (TPM_ST_ATTEST_NV_DIGEST) is not produced by this simulator.
/// </para>
/// <list type="bullet">
///   <item><description>certifyInfo (TPM2B_ATTEST): the signed attestation (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_NV). The signature is over its raw bytes.</description></item>
///   <item><description>signature (TPMT_SIGNATURE): sigAlg (TPMI_ALG_SIG_SCHEME, 2 bytes) selecting a <see cref="TpmuSignature"/> member.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class NvCertifyResponse: IDisposable, ITpmWireType
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

    private NvCertifyResponse(Tpm2bAttest certifyInfo, TpmAlgIdConstants signatureAlgorithm, TpmuSignature signature)
    {
        CertifyInfo = certifyInfo;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
    }

    /// <summary>
    /// Parses a TPM2_NV_Certify response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed NV-certify response.</returns>
    public static NvCertifyResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bAttest certifyInfo = Tpm2bAttest.Parse(ref reader, pool);
        try
        {
            //A TPM2_NV_Certify response's attestation type is fixed to TPM_ST_ATTEST_NV in this simulator (the
            //TPMS_NV_DIGEST_CERTIFY_INFO form is not modelled, Part 3, §31.16). Reject a type-confused body here
            //rather than surfacing it as a successful response whose Attested.Nv is null and faults the first
            //consumer that reads it.
            if(certifyInfo.AttestationData.Type != TpmStConstants.TPM_ST_ATTEST_NV)
            {
                throw new InvalidOperationException(
                    $"TPM2_NV_Certify response attestation type must be TPM_ST_ATTEST_NV but was {certifyInfo.AttestationData.Type}.");
            }

            var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
            TpmuSignature signature = TpmuSignature.Parse(sigAlg, ref reader, pool);

            return new NvCertifyResponse(certifyInfo, sigAlg, signature);
        }
        catch
        {
            //A mismatched type or an unsupported signature scheme must not leak the pooled attestation buffer.
            certifyInfo.Dispose();
            throw;
        }
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

    private string DebuggerDisplay => $"NvCertifyResponse({CertifyInfo}, {SignatureAlgorithm}, {Signature})";
}
