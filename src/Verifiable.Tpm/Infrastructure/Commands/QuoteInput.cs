using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Quote command (CC = 0x00000158).
/// </summary>
/// <remarks>
/// <para>
/// Quotes a selected set of PCRs: the TPM builds a TPMS_ATTEST over the PCR composite digest plus the caller's
/// <see cref="QualifyingData"/> nonce and signs it with the key referenced by <see cref="SignHandle"/>. The
/// signing key must have the <c>sign</c> attribute; an attestation key (AK) is a restricted signing key, but a
/// non-restricted signing key quotes equally well — the TPM signs its own TPM_GENERATED structure either way.
/// </para>
/// <para>
/// Command structure (TPM 2.0 Part 3, Section 18.4):
/// </para>
/// <list type="bullet">
///   <item><description>signHandle (TPMI_DH_OBJECT): Handle of the signing key. Requires authorization.</description></item>
///   <item><description>qualifyingData (TPM2B_DATA): Caller-supplied data (a nonce) echoed in the attestation's extraData.</description></item>
///   <item><description>inScheme (TPMT_SIG_SCHEME): The signing scheme (algorithm + hash algorithm).</description></item>
///   <item><description>PCRselect (TPML_PCR_SELECTION): The PCRs to quote.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class QuoteInput: ITpmCommandInput, IDisposable
{
    private bool Disposed { get; set; }

    private IMemoryOwner<byte> QualifyingDataOwner { get; }

    private TpmlPcrSelection PcrSelection { get; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Quote;

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
    /// Gets the hash algorithm for the signing scheme; the TPM also uses it to compute the PCR composite digest.
    /// </summary>
    public TpmAlgIdConstants SchemeHashAlg { get; }

    /// <summary>
    /// Creates a TPM2_Quote input for ECDSA signing.
    /// </summary>
    /// <param name="signHandle">The handle of the ECDSA signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the ECDSA scheme.</param>
    /// <param name="pcrSelection">The PCRs to quote. Ownership is transferred.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="QuoteInput"/>.</returns>
    public static QuoteInput ForEcdsa(
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        TpmlPcrSelection pcrSelection,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_ECDSA, schemeHashAlg, pcrSelection, pool);
    }

    /// <summary>
    /// Creates a TPM2_Quote input for RSASSA (RSA PKCS#1 v1.5) signing.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSASSA scheme.</param>
    /// <param name="pcrSelection">The PCRs to quote. Ownership is transferred.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="QuoteInput"/>.</returns>
    public static QuoteInput ForRsaSsa(
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        TpmlPcrSelection pcrSelection,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_RSASSA, schemeHashAlg, pcrSelection, pool);
    }

    /// <summary>
    /// Creates a TPM2_Quote input for RSAPSS signing.
    /// </summary>
    /// <param name="signHandle">The handle of the RSA signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="schemeHashAlg">The hash algorithm for the RSAPSS scheme.</param>
    /// <param name="pcrSelection">The PCRs to quote. Ownership is transferred.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="QuoteInput"/>.</returns>
    public static QuoteInput ForRsaPss(
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants schemeHashAlg,
        TpmlPcrSelection pcrSelection,
        MemoryPool<byte> pool)
    {
        return Create(signHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_RSAPSS, schemeHashAlg, pcrSelection, pool);
    }

    /// <summary>
    /// Creates a TPM2_Quote input for the given signing scheme.
    /// </summary>
    /// <param name="signHandle">The handle of the signing key.</param>
    /// <param name="qualifyingData">The caller nonce echoed into the attestation.</param>
    /// <param name="signatureScheme">The signing scheme algorithm (TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).</param>
    /// <param name="schemeHashAlg">The hash algorithm for the scheme.</param>
    /// <param name="pcrSelection">The PCRs to quote. Ownership is transferred.</param>
    /// <param name="pool">The memory pool for the qualifying-data buffer.</param>
    /// <returns>A new <see cref="QuoteInput"/>.</returns>
    public static QuoteInput Create(
        TpmiDhObject signHandle,
        ReadOnlySpan<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        TpmlPcrSelection pcrSelection,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pcrSelection);
        ArgumentNullException.ThrowIfNull(pool);
        IMemoryOwner<byte> owner = pool.Rent(qualifyingData.Length);
        qualifyingData.CopyTo(owner.Memory.Span);

        return new QuoteInput(
            signHandle, owner, owner.Memory.Slice(0, qualifyingData.Length), signatureScheme, schemeHashAlg, pcrSelection);
    }

    private QuoteInput(
        TpmiDhObject signHandle,
        IMemoryOwner<byte> qualifyingDataOwner,
        ReadOnlyMemory<byte> qualifyingData,
        TpmAlgIdConstants signatureScheme,
        TpmAlgIdConstants schemeHashAlg,
        TpmlPcrSelection pcrSelection)
    {
        SignHandle = signHandle;
        QualifyingDataOwner = qualifyingDataOwner;
        QualifyingData = qualifyingData;
        SignatureScheme = signatureScheme;
        SchemeHashAlg = schemeHashAlg;
        PcrSelection = pcrSelection;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //TPMT_SIG_SCHEME: scheme (UINT16) + hashAlg (UINT16).
        const int TpmtSigSchemeSize = sizeof(ushort) + sizeof(ushort);

        return sizeof(uint) +                               //signHandle (TPMI_DH_OBJECT)
               sizeof(ushort) + QualifyingData.Length +     //TPM2B_DATA: size prefix + bytes
               TpmtSigSchemeSize +
               PcrSelection.GetSerializedSize();
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
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
        PcrSelection.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            QualifyingDataOwner.Dispose();
            PcrSelection.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"QuoteInput(Key={SignHandle}, Nonce={QualifyingData.Length} bytes, Scheme={SignatureScheme}, Hash={SchemeHashAlg})";
}
