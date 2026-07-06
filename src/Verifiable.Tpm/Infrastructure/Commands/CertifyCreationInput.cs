using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_CertifyCreation command (CC = 0x0000014A).
/// </summary>
/// <remarks>
/// <para>
/// Certifies that the object referenced by <see cref="ObjectHandle"/> was created by the TPM with
/// <see cref="CreationHash"/>, by re-verifying the caller-supplied <see cref="CreationTicket"/>: the TPM builds a
/// TPMS_ATTEST over the object's Name and <see cref="CreationHash"/> plus the caller's <see cref="QualifyingData"/>
/// nonce, and signs it with the key referenced by <see cref="SignHandle"/>.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 18.3, Table 88):
/// </para>
/// <list type="bullet">
///   <item><description>signHandle (TPMI_DH_OBJECT+): The signing key. Requires authorization (USER role).</description></item>
///   <item><description>objectHandle (TPMI_DH_OBJECT): The object whose creation is certified. Requires no authorization.</description></item>
///   <item><description>qualifyingData (TPM2B_DATA): Caller-supplied data (a nonce) echoed in the attestation's extraData.</description></item>
///   <item><description>creationHash (TPM2B_DIGEST): The creation hash the certified object's creation reported.</description></item>
///   <item><description>inScheme (TPMT_SIG_SCHEME): The signing scheme (algorithm + hash algorithm).</description></item>
///   <item><description>creationTicket (TPMT_TK_CREATION): The ticket the certified object's creation returned.</description></item>
/// </list>
/// <para>
/// Only <see cref="SignHandle"/> requires authorization, so the executor is given a single authorization session
/// for it; <see cref="ObjectHandle"/> carries no session at all.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class CertifyCreationInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> QualifyingDataOwner { get; }

    private IMemoryOwner<byte> CreationHashOwner { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_CertifyCreation;

    /// <summary>
    /// Gets the handle of the signing key.
    /// </summary>
    public TpmiDhObject SignHandle { get; }

    /// <summary>
    /// Gets the handle of the object whose creation is certified.
    /// </summary>
    public TpmiDhObject ObjectHandle { get; }

    /// <summary>
    /// Gets the qualifying data (nonce) echoed into the attestation's extraData.
    /// </summary>
    public ReadOnlyMemory<byte> QualifyingData { get; }

    /// <summary>
    /// Gets the creation hash the certified object's creation reported.
    /// </summary>
    public ReadOnlyMemory<byte> CreationHash { get; }

    /// <summary>
    /// Gets the signing scheme algorithm (TPMI_ALG_SIG_SCHEME): TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS.
    /// </summary>
    public TpmAlgIdConstants SignatureScheme { get; }

    /// <summary>
    /// Gets the hash algorithm for the signing scheme.
    /// </summary>
    public TpmAlgIdConstants SchemeHashAlg { get; }

    /// <summary>
    /// Gets the creation ticket the certified object's creation returned. Not owned by this instance: the caller
    /// retains ownership (typically a <see cref="CreatePrimaryResponse"/> or <see cref="CreateResponse"/>) and must
    /// keep it alive until this input has been sent.
    /// </summary>
    public TpmtTkCreation CreationTicket { get; }

    /// <summary>
    /// Creates a TPM2_CertifyCreation input for ECDSA signing.
    /// </summary>
    /// <param name="signHandle">The handle of the ECDSA signing key.</param>
    /// <param name="objectHandle">The handle of the object whose creation is certified.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="creationHash">The creation hash the certified object's creation reported.</param>
    /// <param name="creationTicket">The creation ticket the certified object's creation returned. Not owned by the returned input.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the ECDSA scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data and creation-hash buffers.</param>
    /// <returns>A new <see cref="CertifyCreationInput"/>.</returns>
    public static CertifyCreationInput ForEcdsa(
        TpmiDhObject signHandle,
        TpmiDhObject objectHandle,
        ReadOnlySpan<byte> qualifyingData,
        ReadOnlySpan<byte> creationHash,
        TpmtTkCreation creationTicket,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, objectHandle, qualifyingData, creationHash, creationTicket, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_CertifyCreation input for RSASSA (RSA PKCS#1 v1.5) signing.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="objectHandle">The handle of the object whose creation is certified.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="creationHash">The creation hash the certified object's creation reported.</param>
    /// <param name="creationTicket">The creation ticket the certified object's creation returned. Not owned by the returned input.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSASSA scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data and creation-hash buffers.</param>
    /// <returns>A new <see cref="CertifyCreationInput"/>.</returns>
    public static CertifyCreationInput ForRsaSsa(
        TpmiDhObject signHandle,
        TpmiDhObject objectHandle,
        ReadOnlySpan<byte> qualifyingData,
        ReadOnlySpan<byte> creationHash,
        TpmtTkCreation creationTicket,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, objectHandle, qualifyingData, creationHash, creationTicket, TpmAlgIdConstants.TPM_ALG_RSASSA, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_CertifyCreation input for RSAPSS signing.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="objectHandle">The handle of the object whose creation is certified.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="creationHash">The creation hash the certified object's creation reported.</param>
    /// <param name="creationTicket">The creation ticket the certified object's creation returned. Not owned by the returned input.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSAPSS scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data and creation-hash buffers.</param>
    /// <returns>A new <see cref="CertifyCreationInput"/>.</returns>
    public static CertifyCreationInput ForRsaPss(
        TpmiDhObject signHandle,
        TpmiDhObject objectHandle,
        ReadOnlySpan<byte> qualifyingData,
        ReadOnlySpan<byte> creationHash,
        TpmtTkCreation creationTicket,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, objectHandle, qualifyingData, creationHash, creationTicket, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, pool);
    }

    /// <summary>
    /// Creates a TPM2_CertifyCreation input for the given signing scheme.
    /// </summary>
    /// <param name="signHandle">The handle of the signing key.</param>
    /// <param name="objectHandle">The handle of the object whose creation is certified.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="creationHash">The creation hash the certified object's creation reported.</param>
    /// <param name="creationTicket">The creation ticket the certified object's creation returned. Not owned by the returned input.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
    /// <param name="schemeHashAlg">The hash algorithm for the scheme.</param>
    /// <param name="pool">The memory pool for the qualifying-data and creation-hash buffers.</param>
    /// <returns>A new <see cref="CertifyCreationInput"/>.</returns>
    public static CertifyCreationInput Create(
        TpmiDhObject signHandle,
        TpmiDhObject objectHandle,
        ReadOnlySpan<byte> qualifyingData,
        ReadOnlySpan<byte> creationHash,
        TpmtTkCreation creationTicket,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(creationTicket);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> qualifyingDataOwner = pool.Rent(qualifyingData.Length);
        qualifyingData.CopyTo(qualifyingDataOwner.Memory.Span);

        IMemoryOwner<byte> creationHashOwner = pool.Rent(creationHash.Length);
        creationHash.CopyTo(creationHashOwner.Memory.Span);

        return new CertifyCreationInput(
            signHandle,
            objectHandle,
            qualifyingDataOwner,
            qualifyingDataOwner.Memory.Slice(0, qualifyingData.Length),
            creationHashOwner,
            creationHashOwner.Memory.Slice(0, creationHash.Length),
            creationTicket,
            signatureScheme,
            schemeHashAlg);
    }

    private CertifyCreationInput(
        TpmiDhObject signHandle,
        TpmiDhObject objectHandle,
        IMemoryOwner<byte> qualifyingDataOwner,
        ReadOnlyMemory<byte> qualifyingData,
        IMemoryOwner<byte> creationHashOwner,
        ReadOnlyMemory<byte> creationHash,
        TpmtTkCreation creationTicket,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg)
    {
        SignHandle = signHandle;
        ObjectHandle = objectHandle;
        QualifyingDataOwner = qualifyingDataOwner;
        QualifyingData = qualifyingData;
        CreationHashOwner = creationHashOwner;
        CreationHash = creationHash;
        CreationTicket = creationTicket;
        SignatureScheme = signatureScheme;
        SchemeHashAlg = schemeHashAlg;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //TPMT_SIG_SCHEME: scheme (UINT16) + hashAlg (UINT16).
        const int TpmtSigSchemeSize = sizeof(ushort) + sizeof(ushort);

        return (2 * sizeof(uint)) +                          //signHandle + objectHandle (TPMI_DH_OBJECT).
               sizeof(ushort) + QualifyingData.Length +      //TPM2B_DATA: size prefix + bytes.
               sizeof(ushort) + CreationHash.Length +        //TPM2B_DIGEST: size prefix + bytes.
               TpmtSigSchemeSize +
               CreationTicket.SerializedSize;
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        SignHandle.WriteTo(ref writer);
        ObjectHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        writer.WriteUInt16((ushort)QualifyingData.Length);
        writer.WriteBytes(QualifyingData.Span);
        writer.WriteUInt16((ushort)CreationHash.Length);
        writer.WriteBytes(CreationHash.Span);
        writer.WriteUInt16((ushort)SignatureScheme);
        writer.WriteUInt16((ushort)SchemeHashAlg);
        CreationTicket.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            QualifyingDataOwner.Dispose();
            CreationHashOwner.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"CertifyCreationInput(Key={SignHandle}, Object={ObjectHandle}, Nonce={QualifyingData.Length} bytes, Scheme={SignatureScheme}, Hash={SchemeHashAlg})";
}
