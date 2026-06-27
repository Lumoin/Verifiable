using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Certify command (CC = 0x00000148).
/// </summary>
/// <remarks>
/// <para>
/// Certifies that the object referenced by <see cref="ObjectHandle"/> is loaded in the TPM: the TPM builds a
/// TPMS_ATTEST over the object's Name (and Qualified Name) plus the caller's <see cref="QualifyingData"/> nonce,
/// and signs it with the key referenced by <see cref="SignHandle"/>. This is the cross-key attestation an
/// attestation key (AK) uses to vouch for another key it shares a TPM with.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 18.2):
/// </para>
/// <list type="bullet">
///   <item><description>objectHandle (TPMI_DH_OBJECT): The object to certify. Requires authorization (ADMIN role).</description></item>
///   <item><description>signHandle (TPMI_DH_OBJECT): The signing key. Requires authorization (USER role).</description></item>
///   <item><description>qualifyingData (TPM2B_DATA): Caller-supplied data (a nonce) echoed in the attestation's extraData.</description></item>
///   <item><description>inScheme (TPMT_SIG_SCHEME): The signing scheme (algorithm + hash algorithm).</description></item>
/// </list>
/// <para>
/// The two handles both require authorization, so the executor is given two authorization sessions in handle
/// order: the object's first, the signing key's second. ADMIN-role authorization of the object is satisfied by
/// its authValue only when its <c>adminWithPolicy</c> attribute is clear.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CertifyInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> QualifyingDataOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Certify;

    /// <summary>
    /// Gets the handle of the object being certified.
    /// </summary>
    public TpmiDhObject ObjectHandle { get; }

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
    /// Creates a TPM2_Certify input for ECDSA signing.
    /// </summary>
    /// <param name="objectHandle">The handle of the object to certify.</param>
    /// <param name="signHandle">The handle of the ECDSA signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the ECDSA scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="CertifyInput"/>.</returns>
    public static CertifyInput ForEcdsa(
        TpmiDhObject objectHandle,
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        return Create(objectHandle, signHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_Certify input for the given signing scheme.
    /// </summary>
    /// <param name="objectHandle">The handle of the object to certify.</param>
    /// <param name="signHandle">The handle of the signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
    /// <param name="schemeHashAlg">The hash algorithm for the scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="CertifyInput"/>.</returns>
    public static CertifyInput Create(
        TpmiDhObject objectHandle,
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> owner = pool.Rent(qualifyingData.Length);
        qualifyingData.CopyTo(owner.Memory.Span);

        return new CertifyInput(
            objectHandle, signHandle, owner, owner.Memory.Slice(0, qualifyingData.Length), signatureScheme, schemeHashAlg);
    }

    private CertifyInput(
        TpmiDhObject objectHandle,
        TpmiDhObject signHandle,
        IMemoryOwner<byte> qualifyingDataOwner,
        ReadOnlyMemory<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg)
    {
        ObjectHandle = objectHandle;
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

        return (2 * sizeof(uint)) +                         //objectHandle + signHandle (TPMI_DH_OBJECT)
               sizeof(ushort) + QualifyingData.Length +     //TPM2B_DATA: size prefix + bytes
               TpmtSigSchemeSize;
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        ObjectHandle.WriteTo(ref writer);
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

    private string DebuggerDisplay => $"CertifyInput(Object={ObjectHandle}, Key={SignHandle}, Nonce={QualifyingData.Length} bytes, Scheme={SignatureScheme}, Hash={SchemeHashAlg})";
}
