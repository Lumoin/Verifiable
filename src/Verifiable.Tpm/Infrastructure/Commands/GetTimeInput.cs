using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_GetTime command (CC = 0x0000014C).
/// </summary>
/// <remarks>
/// <para>
/// Attests the TPM's current time and clock/reset state: the TPM builds a TPMS_ATTEST over a zero-time image
/// (this simulator models no clock state) plus the caller's <see cref="QualifyingData"/> nonce, and signs it with
/// the key referenced by <see cref="SignHandle"/>. This command requires Endorsement authorization.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 18.7, Table 96):
/// </para>
/// <list type="bullet">
///   <item><description>privacyAdminHandle (TPMI_RH_ENDORSEMENT): Fixed to TPM_RH_ENDORSEMENT. Requires authorization (USER role).</description></item>
///   <item><description>signHandle (TPMI_DH_OBJECT+): The signing key. Requires authorization (USER role).</description></item>
///   <item><description>qualifyingData (TPM2B_DATA): Caller-supplied data (a nonce) echoed in the attestation's extraData.</description></item>
///   <item><description>inScheme (TPMT_SIG_SCHEME): The signing scheme (algorithm + hash algorithm).</description></item>
/// </list>
/// <para>
/// Both handles require authorization, so the executor is given two authorization sessions in handle order: the
/// Endorsement hierarchy's first, the signing key's second. Both are empty-auth password sessions in this slice.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class GetTimeInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> QualifyingDataOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_GetTime;

    /// <summary>
    /// Gets the privacy administrator handle. TPMI_RH_ENDORSEMENT has exactly one legal value
    /// (<see cref="TpmRh.TPM_RH_ENDORSEMENT"/>); this is a plain field (rather than a hardcoded constant) so a
    /// caller can exercise the simulator's rejection of any other value.
    /// </summary>
    public TpmRh PrivacyAdminHandle { get; }

    /// <summary>
    /// Gets the handle of the signing key.
    /// </summary>
    public TpmiDhObject SignHandle { get; }

    /// <summary>
    /// Gets the qualifying data (nonce) echoed into the attestation's extraData.
    /// </summary>
    public ReadOnlyMemory<byte> QualifyingData { get; }

    /// <summary>
    /// Gets the signing scheme algorithm (TPMI_ALG_SIG_SCHEME): TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS.
    /// </summary>
    public TpmAlgIdConstants SignatureScheme { get; }

    /// <summary>
    /// Gets the hash algorithm for the signing scheme.
    /// </summary>
    public TpmAlgIdConstants SchemeHashAlg { get; }

    /// <summary>
    /// Creates a TPM2_GetTime input for ECDSA signing, with the standard <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>
    /// privacy administrator handle.
    /// </summary>
    /// <param name="signHandle">The handle of the ECDSA signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the ECDSA scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetTimeInput"/>.</returns>
    public static GetTimeInput ForEcdsa(
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        return Create(TpmRh.TPM_RH_ENDORSEMENT, signHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_GetTime input for RSASSA (RSA PKCS#1 v1.5) signing, with the standard
    /// <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> privacy administrator handle.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSASSA scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetTimeInput"/>.</returns>
    public static GetTimeInput ForRsaSsa(
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        return Create(TpmRh.TPM_RH_ENDORSEMENT, signHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_RSASSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_GetTime input for RSAPSS signing, with the standard <see cref="TpmRh.TPM_RH_ENDORSEMENT"/>
    /// privacy administrator handle.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSAPSS scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetTimeInput"/>.</returns>
    public static GetTimeInput ForRsaPss(
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        return Create(TpmRh.TPM_RH_ENDORSEMENT, signHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_GetTime input for the given privacy administrator handle and signing scheme. A caller-chosen
    /// <paramref name="privacyAdminHandle"/> other than <see cref="TpmRh.TPM_RH_ENDORSEMENT"/> is accepted here (the
    /// simulator rejects it at the command boundary) so the rejection itself can be exercised.
    /// </summary>
    /// <param name="privacyAdminHandle">The privacy administrator handle (TPMI_RH_ENDORSEMENT).</param>
    /// <param name="signHandle">The handle of the signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
    /// <param name="schemeHashAlg">The hash algorithm for the scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="GetTimeInput"/>.</returns>
    public static GetTimeInput Create(
        TpmRh privacyAdminHandle,
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> owner = pool.Rent(qualifyingData.Length);
        qualifyingData.CopyTo(owner.Memory.Span);

        return new GetTimeInput(
            privacyAdminHandle, signHandle, owner, owner.Memory.Slice(0, qualifyingData.Length), signatureScheme, schemeHashAlg);
    }

    private GetTimeInput(
        TpmRh privacyAdminHandle,
        TpmiDhObject signHandle,
        IMemoryOwner<byte> qualifyingDataOwner,
        ReadOnlyMemory<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg)
    {
        PrivacyAdminHandle = privacyAdminHandle;
        SignHandle = signHandle;
        QualifyingDataOwner = qualifyingDataOwner;
        QualifyingData = qualifyingData;
        SignatureScheme = signatureScheme;
        SchemeHashAlg = schemeHashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //TPMT_SIG_SCHEME: scheme (UINT16) + hashAlg (UINT16).
        const int TpmtSigSchemeSize = sizeof(ushort) + sizeof(ushort);

        return (2 * sizeof(uint)) +                         //privacyAdminHandle + signHandle.
               sizeof(ushort) + QualifyingData.Length +     //TPM2B_DATA: size prefix + bytes.
               TpmtSigSchemeSize;
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)PrivacyAdminHandle);
        SignHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        writer.WriteUInt16((ushort)QualifyingData.Length);
        writer.WriteBytes(QualifyingData.Span);
        writer.WriteUInt16((ushort)SignatureScheme);
        writer.WriteUInt16((ushort)SchemeHashAlg);
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

    private string DebuggerDisplay => $"GetTimeInput(PrivacyAdmin={PrivacyAdminHandle}, Key={SignHandle}, Nonce={QualifyingData.Length} bytes, Scheme={SignatureScheme}, Hash={SchemeHashAlg})";
}
