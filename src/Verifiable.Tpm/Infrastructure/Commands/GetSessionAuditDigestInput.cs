using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_GetSessionAuditDigest command (CC = 0x0000014D).
/// </summary>
/// <remarks>
/// <para>
/// Returns a digital signature of an audit session's digest: the TPM builds a TPMS_ATTEST carrying the session's
/// current audit digest and exclusive status, plus the caller's <see cref="QualifyingData"/> nonce, and signs it
/// with the key referenced by <see cref="SignHandle"/>. "This command requires authorization from the privacy
/// administrator of the TPM (expressed with Endorsement Authorization) as well as authorization to use the key
/// associated with signHandle" (TPM 2.0 Library Part 3, clause 18.5.1).
/// </para>
/// <para>
/// Command structure (TPM 2.0 Library Part 3, clause 18.5, Table 103):
/// </para>
/// <list type="bullet">
///   <item><description>privacyAdminHandle (TPMI_RH_ENDORSEMENT): "handle of the privacy administrator (TPM_RH_ENDORSEMENT)". Auth Index 1, Auth Role USER.</description></item>
///   <item><description>signHandle (TPMI_DH_OBJECT+): "handle of the signing key". Auth Index 2, Auth Role USER.</description></item>
///   <item><description>sessionHandle (TPMI_SH_HMAC): "handle of the audit session". Auth Index None.</description></item>
///   <item><description>qualifyingData (TPM2B_DATA): "user-provided qualifying data - may be zero-length".</description></item>
///   <item><description>inScheme (TPMT_SIG_SCHEME+): "signing scheme to use if the scheme for signHandle is TPM_ALG_NULL".</description></item>
/// </list>
/// <para>
/// Both <see cref="PrivacyAdminHandle"/> and <see cref="SignHandle"/> require authorization, so the executor is
/// given two authorization sessions in handle order: the Endorsement hierarchy's first, the signing key's second.
/// <see cref="SessionHandle"/> carries no authorization session of its own — it is the third handle in the area,
/// unauthorized, the same shape TPM2_NV_Certify's unauthorized <c>nvIndex</c> handle has.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class GetSessionAuditDigestInput: ITpmCommandInput, IDisposable
{
    /// <summary>
    /// Whether <see cref="Dispose"/> has already released <see cref="QualifyingDataOwner"/>.
    /// </summary>
    private bool Disposed { get; set; }

    /// <summary>
    /// The pooled rental backing <see cref="QualifyingData"/>. OWNED, released by <see cref="Dispose"/>.
    /// </summary>
    private IMemoryOwner<byte> QualifyingDataOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_GetSessionAuditDigest;

    /// <inheritdoc/>
    /// <remarks>
    /// <c>qualifyingData</c> (<c>TPM2B_DATA</c>) is the first entry of the parameter area and carries an explicit
    /// size field (TPM 2.0 Library Part 3, clause 18.5, Table 103), which is what TPM 2.0 Library Part 1, clause
    /// 18.1 requires of an encryptable parameter and what clause 15.4 restates ("for a command or response
    /// parameter to be encrypted, it must be the first parameter and it must be a TPM2B type"). A session without
    /// the <c>decrypt</c> attribute is unaffected; the attribute is what asks the TPM to decrypt the parameter
    /// after the command HMACs verify, so the caller nonce this command echoes into the attestation's
    /// <c>extraData</c> never crosses the bus in the clear.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

    /// <summary>
    /// Gets the privacy administrator handle. TPMI_RH_ENDORSEMENT has exactly one legal value
    /// (<see cref="TpmRh.TPM_RH_ENDORSEMENT"/>); this is a plain field (rather than a hardcoded constant) so a
    /// caller can exercise the simulator's rejection of any other value.
    /// </summary>
    public TpmRh PrivacyAdminHandle { get; }

    /// <summary>
    /// Gets the handle of the signing key, or <see cref="TpmRh.TPM_RH_NULL"/> for the NULL signer (Part 3, clause
    /// 18.1: "the attestation block is 'signed' with the NULL Signature").
    /// </summary>
    public TpmiDhObject SignHandle { get; }

    /// <summary>
    /// Gets the handle of the audit session whose digest is attested.
    /// </summary>
    public TpmiShHmac SessionHandle { get; }

    /// <summary>
    /// Gets the qualifying data (nonce) echoed into the attestation's extraData.
    /// </summary>
    public ReadOnlyMemory<byte> QualifyingData { get; }

    /// <summary>
    /// Gets the signing scheme algorithm (TPMI_ALG_SIG_SCHEME+): TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, or
    /// TPM_ALG_NULL for the NULL signer.
    /// </summary>
    public TpmAlgIdConstants SignatureScheme { get; }

    /// <summary>
    /// Gets the hash algorithm for the signing scheme, or TPM_ALG_NULL for the NULL signer.
    /// </summary>
    public TpmAlgIdConstants SchemeHashAlg { get; }

    /// <summary>
    /// Creates a TPM2_GetSessionAuditDigest input for ECDSA signing, with the standard
    /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> privacy administrator handle.
    /// </summary>
    /// <param name="signHandle">The handle of the ECDSA signing key.</param>
    /// <param name="sessionHandle">The handle of the audit session.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the ECDSA scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetSessionAuditDigestInput"/>.</returns>
    public static GetSessionAuditDigestInput ForEcdsa(
        TpmiDhObject signHandle,
        TpmiShHmac sessionHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(TpmRh.TPM_RH_ENDORSEMENT, signHandle, sessionHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_GetSessionAuditDigest input for RSASSA (RSA PKCS#1 v1.5) signing, with the standard
    /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> privacy administrator handle.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="sessionHandle">The handle of the audit session.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSASSA scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetSessionAuditDigestInput"/>.</returns>
    public static GetSessionAuditDigestInput ForRsaSsa(
        TpmiDhObject signHandle,
        TpmiShHmac sessionHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(TpmRh.TPM_RH_ENDORSEMENT, signHandle, sessionHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_RSASSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_GetSessionAuditDigest input for RSAPSS signing, with the standard
    /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> privacy administrator handle.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="sessionHandle">The handle of the audit session.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSAPSS scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetSessionAuditDigestInput"/>.</returns>
    public static GetSessionAuditDigestInput ForRsaPss(
        TpmiDhObject signHandle,
        TpmiShHmac sessionHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        return Create(TpmRh.TPM_RH_ENDORSEMENT, signHandle, sessionHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_GetSessionAuditDigest input for the NULL signer: <c>signHandle</c> is
    /// <see cref="TpmRh.TPM_RH_NULL"/>, so "all of the actions of the command are performed, and the attestation
    /// block is 'signed' with the NULL Signature" (TPM 2.0 Library Part 3, clause 18.1); <c>scheme</c> is "still
    /// required to be a valid signing scheme (may be TPM_ALG_NULL)" (ibid.) and is set to TPM_ALG_NULL here.
    /// </summary>
    /// <param name="sessionHandle">The handle of the audit session.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetSessionAuditDigestInput"/>.</returns>
    public static GetSessionAuditDigestInput ForNullSigner(
        TpmiShHmac sessionHandle,
        ReadOnlySpan<byte> qualifyingData,
        BaseMemoryPool pool)
    {
        return Create(
            TpmRh.TPM_RH_ENDORSEMENT,
            TpmiDhObject.FromValue((uint)TpmRh.TPM_RH_NULL),
            sessionHandle,
            qualifyingData,
            TpmAlgIdConstants.TPM_ALG_NULL,
            TpmAlgIdConstants.TPM_ALG_NULL,
            pool);
    }

    /// <summary>
    /// Creates a TPM2_GetSessionAuditDigest input for the given privacy administrator handle and signing scheme. A
    /// caller-chosen <paramref name="privacyAdminHandle"/> other than <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> is
    /// accepted here (the simulator rejects it at the command boundary) so the rejection itself can be exercised.
    /// </summary>
    /// <param name="privacyAdminHandle">The privacy administrator handle (TPMI_RH_ENDORSEMENT).</param>
    /// <param name="signHandle">The handle of the signing key, or <see cref="TpmRh.TPM_RH_NULL"/>.</param>
    /// <param name="sessionHandle">The handle of the audit session.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, or TPM_ALG_NULL).</param>
    /// <param name="schemeHashAlg">The hash algorithm for the scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetSessionAuditDigestInput"/>.</returns>
    public static GetSessionAuditDigestInput Create(
        TpmRh privacyAdminHandle,
        TpmiDhObject signHandle,
        TpmiShHmac sessionHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        //An EMPTY qualifyingData is legal — a TPM2B parameter may declare a zero size, and Part 3, clause 5.7
        //notes that "the size of the parameter to be encrypted can be zero" — so the rental floor keeps a
        //zero-length value expressible; the slice below is what fixes the parameter's declared width.
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(qualifyingData.Length, 1));
        qualifyingData.CopyTo(owner.Memory.Span);

        return new GetSessionAuditDigestInput(
            privacyAdminHandle, signHandle, sessionHandle, owner, owner.Memory.Slice(0, qualifyingData.Length), signatureScheme, schemeHashAlg);
    }

    /// <summary>
    /// Initializes a TPM2_GetSessionAuditDigest input from its already-resolved handles, rented qualifying-data
    /// buffer, and signing scheme.
    /// </summary>
    /// <param name="privacyAdminHandle">The privacy administrator handle (TPMI_RH_ENDORSEMENT).</param>
    /// <param name="signHandle">The handle of the signing key, or <see cref="TpmRh.TPM_RH_NULL"/>.</param>
    /// <param name="sessionHandle">The handle of the audit session.</param>
    /// <param name="qualifyingDataOwner">The pooled rental backing <paramref name="qualifyingData"/>. Ownership is transferred.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, or TPM_ALG_NULL).</param>
    /// <param name="schemeHashAlg">The hash algorithm for the scheme.</param>
    private GetSessionAuditDigestInput(
        TpmRh privacyAdminHandle,
        TpmiDhObject signHandle,
        TpmiShHmac sessionHandle,
        IMemoryOwner<byte> qualifyingDataOwner,
        ReadOnlyMemory<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg)
    {
        PrivacyAdminHandle = privacyAdminHandle;
        SignHandle = signHandle;
        SessionHandle = sessionHandle;
        QualifyingDataOwner = qualifyingDataOwner;
        QualifyingData = qualifyingData;
        SignatureScheme = signatureScheme;
        SchemeHashAlg = schemeHashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //TPMT_SIG_SCHEME (TPM 2.0 Library Part 2, clause 11.2.1.5, Table 183): scheme (UINT16) selector, plus a
        //hashAlg (UINT16) detail pair only when the scheme is not TPM_ALG_NULL — Table 183's [scheme]details
        //is absent entirely for the NULL scheme (clause 11.2.1.4, Table 182, whose "null" row carries an empty
        //Type column against selector TPM_ALG_NULL), so a NULL SignatureScheme omits the trailing octets.
        int schemeSize = sizeof(ushort) + (SignatureScheme == TpmAlgIdConstants.TPM_ALG_NULL ? 0 : sizeof(ushort));

        return (3 * sizeof(uint)) +                          //privacyAdminHandle + signHandle + sessionHandle.
               sizeof(ushort) + QualifyingData.Length +      //TPM2B_DATA: size prefix + bytes.
               schemeSize;
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)PrivacyAdminHandle);
        SignHandle.WriteTo(ref writer);
        SessionHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        writer.WriteUInt16((ushort)QualifyingData.Length);
        writer.WriteBytes(QualifyingData.Span);
        writer.WriteUInt16((ushort)SignatureScheme);

        //Table 183's [scheme]details is present only for a non-NULL scheme — a NULL SignatureScheme selects no
        //TPMU_SIG_SCHEME member at all, so SchemeHashAlg is not framed for it.
        if(SignatureScheme != TpmAlgIdConstants.TPM_ALG_NULL)
        {
            writer.WriteUInt16((ushort)SchemeHashAlg);
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            QualifyingDataOwner.Dispose();
            Disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the handles, the octet count of <see cref="QualifyingData"/>, and the
    /// signing scheme, never the qualifying-data octets themselves.
    /// </summary>
    private string DebuggerDisplay =>
        $"GetSessionAuditDigestInput(PrivacyAdmin={PrivacyAdminHandle}, Key={SignHandle}, Session={SessionHandle}, Nonce={QualifyingData.Length} bytes, Scheme={SignatureScheme}, Hash={SchemeHashAlg})";
}
