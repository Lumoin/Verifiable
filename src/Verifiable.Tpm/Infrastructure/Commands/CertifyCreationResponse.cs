using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_CertifyCreation command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, Section 18.3) — identical shape to TPM2_Certify's response:
/// </para>
/// <list type="bullet">
///   <item><description>certifyInfo (TPM2B_ATTEST): the signed attestation (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_CREATION). The signature is over its raw bytes.</description></item>
///   <item><description>signature (TPMT_SIGNATURE): sigAlg (TPMI_ALG_SIG_SCHEME, 2 bytes) selecting a <see cref="TpmuSignature"/> member.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CertifyCreationResponse: IDisposable, ITpmWireType
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

    private CertifyCreationResponse(Tpm2bAttest certifyInfo, TpmAlgIdConstants signatureAlgorithm, TpmuSignature signature)
    {
        CertifyInfo = certifyInfo;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
    }

    /// <summary>
    /// Parses a TPM2_CertifyCreation response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed certify-creation response.</returns>
    public static CertifyCreationResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bAttest certifyInfo = Tpm2bAttest.Parse(ref reader, pool);
        try
        {
            //A TPM2_CertifyCreation response's attestation type is fixed to TPM_ST_ATTEST_CREATION (Part 3, §18.3).
            //Reject a type-confused body here rather than surfacing it as a successful response whose
            //Attested.Creation is null and faults the first consumer that reads it.
            if(certifyInfo.AttestationData.Type != TpmStConstants.TPM_ST_ATTEST_CREATION)
            {
                throw new InvalidOperationException(
                    $"TPM2_CertifyCreation response attestation type must be TPM_ST_ATTEST_CREATION but was {certifyInfo.AttestationData.Type}.");
            }

            var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
            TpmuSignature signature = TpmuSignature.Parse(sigAlg, ref reader, pool);

            return new CertifyCreationResponse(certifyInfo, sigAlg, signature);
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

    private string DebuggerDisplay => $"CertifyCreationResponse({CertifyInfo}, {SignatureAlgorithm}, {Signature})";
}
