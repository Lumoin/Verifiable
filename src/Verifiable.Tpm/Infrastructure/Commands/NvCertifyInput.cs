using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_NV_Certify command (CC = 0x00000184).
/// </summary>
/// <remarks>
/// <para>
/// Certifies the contents of an NV Index: the TPM builds a TPMS_ATTEST over the Index's Name and the octets at
/// <see cref="Offset"/> for <see cref="Size"/> octets, plus the caller's <see cref="QualifyingData"/> nonce, and
/// signs it with the key referenced by <see cref="SignHandle"/>. Only the TPMS_NV_CERTIFY_INFO form (a non-zero
/// <see cref="Size"/> or <see cref="Offset"/>) is modelled; requesting both zero selects the unmodelled
/// TPMS_NV_DIGEST_CERTIFY_INFO form.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 31.16, Table 238):
/// </para>
/// <list type="bullet">
///   <item><description>signHandle (TPMI_DH_OBJECT+): The signing key. Requires authorization (USER role).</description></item>
///   <item><description>authHandle (TPMI_RH_NV_AUTH): The source of the Index authorization value; for Index authorization this equals <see cref="NvIndex"/>. Requires authorization (USER role).</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX): The NV Index whose contents are certified. Requires no authorization.</description></item>
///   <item><description>qualifyingData (TPM2B_DATA): Caller-supplied data (a nonce) echoed in the attestation's extraData.</description></item>
///   <item><description>inScheme (TPMT_SIG_SCHEME): The signing scheme (algorithm + hash algorithm).</description></item>
///   <item><description>size (UINT16): The number of octets to certify.</description></item>
///   <item><description>offset (UINT16): The octet offset into the Index data area.</description></item>
/// </list>
/// <para>
/// Both <see cref="SignHandle"/> and <see cref="AuthHandle"/> require authorization, so the executor is given two
/// authorization sessions in handle order: the signing key's first, the Index authorization's second.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class NvCertifyInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> QualifyingDataOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_Certify;

    /// <summary>
    /// Gets the handle of the signing key.
    /// </summary>
    public TpmiDhObject SignHandle { get; }

    /// <summary>
    /// Gets the authorization handle for the NV Index (the Index itself, for Index authorization).
    /// </summary>
    public uint AuthHandle { get; }

    /// <summary>
    /// Gets the handle of the NV Index whose contents are certified.
    /// </summary>
    public uint NvIndex { get; }

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
    /// Gets the number of octets to certify.
    /// </summary>
    public ushort Size { get; }

    /// <summary>
    /// Gets the octet offset into the Index data area.
    /// </summary>
    public ushort Offset { get; }

    /// <summary>
    /// Creates a TPM2_NV_Certify input for ECDSA signing.
    /// </summary>
    /// <param name="signHandle">The handle of the ECDSA signing key.</param>
    /// <param name="authHandle">The NV Index authorization handle.</param>
    /// <param name="nvIndex">The NV Index whose contents are certified.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the ECDSA scheme.</param>
    /// <param name="size">The number of octets to certify.</param>
    /// <param name="offset">The octet offset into the Index data area.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="NvCertifyInput"/>.</returns>
    public static NvCertifyInput ForEcdsa(
        TpmiDhObject signHandle,
        uint authHandle,
        uint nvIndex,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        ushort size,
        ushort offset,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, authHandle, nvIndex, qualifyingData, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, size, offset, pool);
    }

    /// <summary>
    /// Creates a TPM2_NV_Certify input for RSASSA (RSA PKCS#1 v1.5) signing.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="authHandle">The NV Index authorization handle.</param>
    /// <param name="nvIndex">The NV Index whose contents are certified.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSASSA scheme.</param>
    /// <param name="size">The number of octets to certify.</param>
    /// <param name="offset">The octet offset into the Index data area.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="NvCertifyInput"/>.</returns>
    public static NvCertifyInput ForRsaSsa(
        TpmiDhObject signHandle,
        uint authHandle,
        uint nvIndex,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        ushort size,
        ushort offset,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, authHandle, nvIndex, qualifyingData, TpmAlgIdConstants.TPM_ALG_RSASSA, schemeHashAlg, size, offset, pool);
    }

    /// <summary>
    /// Creates a TPM2_NV_Certify input for RSAPSS signing.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="authHandle">The NV Index authorization handle.</param>
    /// <param name="nvIndex">The NV Index whose contents are certified.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSAPSS scheme.</param>
    /// <param name="size">The number of octets to certify.</param>
    /// <param name="offset">The octet offset into the Index data area.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="NvCertifyInput"/>.</returns>
    public static NvCertifyInput ForRsaPss(
        TpmiDhObject signHandle,
        uint authHandle,
        uint nvIndex,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        ushort size,
        ushort offset,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, authHandle, nvIndex, qualifyingData, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, size, offset, pool);
    }

    /// <summary>
    /// Creates a TPM2_NV_Certify input for the given signing scheme.
    /// </summary>
    /// <param name="signHandle">The handle of the signing key.</param>
    /// <param name="authHandle">The NV Index authorization handle.</param>
    /// <param name="nvIndex">The NV Index whose contents are certified.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
    /// <param name="schemeHashAlg">The hash algorithm for the scheme.</param>
    /// <param name="size">The number of octets to certify.</param>
    /// <param name="offset">The octet offset into the Index data area.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="NvCertifyInput"/>.</returns>
    public static NvCertifyInput Create(
        TpmiDhObject signHandle,
        uint authHandle,
        uint nvIndex,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        ushort size,
        ushort offset,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> owner = pool.Rent(qualifyingData.Length);
        qualifyingData.CopyTo(owner.Memory.Span);

        return new NvCertifyInput(
            signHandle, authHandle, nvIndex, owner, owner.Memory.Slice(0, qualifyingData.Length), signatureScheme, schemeHashAlg, size, offset);
    }

    private NvCertifyInput(
        TpmiDhObject signHandle,
        uint authHandle,
        uint nvIndex,
        IMemoryOwner<byte> qualifyingDataOwner,
        ReadOnlyMemory<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        ushort size,
        ushort offset)
    {
        SignHandle = signHandle;
        AuthHandle = authHandle;
        NvIndex = nvIndex;
        QualifyingDataOwner = qualifyingDataOwner;
        QualifyingData = qualifyingData;
        SignatureScheme = signatureScheme;
        SchemeHashAlg = schemeHashAlg;
        Size = size;
        Offset = offset;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //TPMT_SIG_SCHEME: scheme (UINT16) + hashAlg (UINT16).
        const int TpmtSigSchemeSize = sizeof(ushort) + sizeof(ushort);

        return (3 * sizeof(uint)) +                          //signHandle + authHandle + nvIndex.
               sizeof(ushort) + QualifyingData.Length +      //TPM2B_DATA: size prefix + bytes.
               TpmtSigSchemeSize +
               sizeof(ushort) +                               //size.
               sizeof(ushort);                                //offset.
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        SignHandle.WriteTo(ref writer);
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        writer.WriteUInt16((ushort)QualifyingData.Length);
        writer.WriteBytes(QualifyingData.Span);
        writer.WriteUInt16((ushort)SignatureScheme);
        writer.WriteUInt16((ushort)SchemeHashAlg);
        writer.WriteUInt16(Size);
        writer.WriteUInt16(Offset);
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

    private string DebuggerDisplay => $"NvCertifyInput(Key={SignHandle}, Auth=0x{AuthHandle:X8}, NvIndex=0x{NvIndex:X8}, Nonce={QualifyingData.Length} bytes, Scheme={SignatureScheme}, Hash={SchemeHashAlg}, Size={Size}, Offset={Offset})";
}
