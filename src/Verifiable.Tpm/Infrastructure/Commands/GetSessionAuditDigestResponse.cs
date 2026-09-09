using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_GetSessionAuditDigest command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 18.5, Table 104) — the same TPM2B_ATTEST + TPMT_SIGNATURE
/// shape as TPM2_GetTime's response:
/// </para>
/// <list type="bullet">
///   <item><description>auditInfo (TPM2B_ATTEST): "the audit information that was signed" (a marshaled TPMS_ATTEST of type TPM_ST_ATTEST_SESSION_AUDIT). The signature is over its raw bytes.</description></item>
///   <item><description>signature (TPMT_SIGNATURE): "the signature over auditInfo" — sigAlg (TPMI_ALG_SIG_SCHEME, 2 bytes) selecting a <see cref="TpmuSignature"/> member, or TPM_ALG_NULL for the NULL Signature.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class GetSessionAuditDigestResponse: IDisposable, ITpmWireType
{
    /// <summary>
    /// Whether <see cref="Dispose"/> has already released <see cref="AuditInfo"/> and <see cref="Signature"/>.
    /// </summary>
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the signed attestation. Verify the signature over <see cref="Tpm2bAttest.GetRawBytes"/>.
    /// </summary>
    public Tpm2bAttest AuditInfo { get; }

    /// <summary>
    /// Gets the signing algorithm reported by the TPM (the TPMU_SIGNATURE selector), or TPM_ALG_NULL for the
    /// NULL Signature.
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

    /// <summary>
    /// Gets the attested session-audit information (Table 148): the audited session's digest as it stood before
    /// this command, and whether that session was the TPM's exclusive audit session.
    /// </summary>
    public TpmsSessionAuditInfo SessionAudit => AuditInfo.AttestationData.Attested.SessionAudit!;

    /// <summary>
    /// Initializes a TPM2_GetSessionAuditDigest response from its parsed attestation and signature.
    /// </summary>
    /// <param name="auditInfo">The signed attestation. Ownership is transferred.</param>
    /// <param name="signatureAlgorithm">The signing algorithm reported by the TPM (the TPMU_SIGNATURE selector), or TPM_ALG_NULL for the NULL Signature.</param>
    /// <param name="signature">The parsed signature value. Ownership is transferred.</param>
    private GetSessionAuditDigestResponse(Tpm2bAttest auditInfo, TpmAlgIdConstants signatureAlgorithm, TpmuSignature signature)
    {
        AuditInfo = auditInfo;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature;
    }

    /// <summary>
    /// Parses a TPM2_GetSessionAuditDigest response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed get-session-audit-digest response.</returns>
    public static GetSessionAuditDigestResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bAttest auditInfo = Tpm2bAttest.Parse(ref reader, pool);
        try
        {
            //A TPM2_GetSessionAuditDigest response's attestation type is fixed to TPM_ST_ATTEST_SESSION_AUDIT
            //(Part 3, clause 18.5). Reject a type-confused body here rather than surfacing it as a successful
            //response whose Attested.SessionAudit is null and faults the first consumer that reads it.
            if(auditInfo.AttestationData.Type != TpmStConstants.TPM_ST_ATTEST_SESSION_AUDIT)
            {
                throw new InvalidOperationException(
                    $"TPM2_GetSessionAuditDigest response attestation type must be TPM_ST_ATTEST_SESSION_AUDIT but was {auditInfo.AttestationData.Type}.");
            }

            //sigAlg TPM_ALG_NULL is the NULL Signature (Part 3, clause 18.1): TpmuSignature.Parse reads nothing
            //further for it and returns the shared TpmuSignature.Null member.
            var sigAlg = (TpmAlgIdConstants)reader.ReadUInt16();
            TpmuSignature signature = TpmuSignature.Parse(sigAlg, ref reader, pool);

            return new GetSessionAuditDigestResponse(auditInfo, sigAlg, signature);
        }
        catch
        {
            //A mismatched type or an unsupported signature scheme must not leak the pooled attestation buffer.
            auditInfo.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            AuditInfo.Dispose();
            Signature.Dispose();
            Disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the attestation, the signature algorithm, and the signature, using each
    /// carrier's own rendering rather than any raw octets.
    /// </summary>
    private string DebuggerDisplay => $"GetSessionAuditDigestResponse({AuditInfo}, {SignatureAlgorithm}, {Signature})";
}
