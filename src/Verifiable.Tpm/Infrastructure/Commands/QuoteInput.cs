using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

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
/// Command structure (TPM 2.0 Library Part 3, clause 18.4):
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

    /// <inheritdoc/>
    /// <remarks>
    /// <c>qualifyingData</c> (<c>TPM2B_DATA</c>) is the first entry of the parameter area and carries an
    /// explicit size field (TPM 2.0 Library Part 3, clause 18.4, Table 101), which is what TPM 2.0 Library Part 1,
    /// clause 18.1 requires of an encryptable parameter and what clause 15.4 restates ("for a command or response
    /// parameter to be encrypted, it must be the first parameter and it must be a TPM2B type"). A session without
    /// the <c>decrypt</c> attribute is unaffected; the attribute is what asks the TPM to decrypt the parameter
    /// after the command HMACs verify, so the caller nonce this command echoes into the attestation's
    /// <c>extraData</c> never crosses the bus in the clear.
    /// </remarks>
    public bool FirstCommandParameterIsEncryptable => true;

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
        BaseMemoryPool pool)
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
        BaseMemoryPool pool)
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
        BaseMemoryPool pool)
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
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pcrSelection);
        ArgumentNullException.ThrowIfNull(pool);
        //An EMPTY qualifyingData is legal — a TPM2B parameter may declare a zero size, and Part 3, clause 5.7
        //notes that "the size of the parameter to be encrypted can be zero" — so the rental floor keeps a
        //zero-length value expressible; the slice below is what fixes the parameter's declared width.
        IMemoryOwner<byte> owner = pool.Rent(Math.Max(qualifyingData.Length, 1));
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
        //TPMT_SIG_SCHEME (TPM 2.0 Library Part 2, clause 11.2.1.5, Table 183): scheme (UINT16) selector, plus a
        //hashAlg (UINT16) detail pair only when the scheme is not TPM_ALG_NULL — Table 183's [scheme]details
        //is absent entirely for the NULL scheme (clause 11.2.1.4, Table 182, whose "null" row carries an empty
        //Type column against selector TPM_ALG_NULL), so a NULL SignatureScheme omits the trailing octets.
        int schemeSize = sizeof(ushort) + (SignatureScheme == TpmAlgIdConstants.TPM_ALG_NULL ? 0 : sizeof(ushort));

        return sizeof(uint) +                               //signHandle (TPMI_DH_OBJECT)
               sizeof(ushort) + QualifyingData.Length +     //TPM2B_DATA: size prefix + bytes
               schemeSize +
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

        //Table 183's [scheme]details is present only for a non-NULL scheme — a NULL SignatureScheme selects no
        //TPMU_SIG_SCHEME member at all, so SchemeHashAlg is not framed for it.
        if(SignatureScheme != TpmAlgIdConstants.TPM_ALG_NULL)
        {
            writer.WriteUInt16((ushort)SchemeHashAlg);
        }

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
