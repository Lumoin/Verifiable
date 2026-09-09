using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PCR_Extend command (CC = TPM_CC_PCR_Extend, 0x00000182).
/// </summary>
/// <remarks>
/// <para>
/// Extends the register <see cref="PcrHandle"/> names with each entry of <see cref="Digests"/>, in the bank the
/// entry's algorithm identifies: <c>PCR.digest[pcrNum][alg]new = Halg(PCR.digest[pcrNum][alg]old ‖
/// data[alg].buffer)</c> (TPM 2.0 Library Part 3, clause 22.2.1). "If no digest value is specified for a bank,
/// then the PCR in that bank is not modified"; "If a digest is present and the PCR in that bank is not
/// implemented, the digest value is not used"; an entry whose algorithm the TPM does not implement fails the
/// unmarshal with <c>TPM_RC_HASH</c>. <c>TPM_RH_NULL</c> is a legal <c>pcrHandle</c>: "the input parameters are
/// processed but no action is taken by the TPM", a way to probe the implemented algorithms.
/// </para>
/// <para>
/// <see cref="PcrHandle"/> carries Auth Index 1 with Auth Role USER (Table 130): the PCR's authorization value
/// — the EmptyAuth on a PC Client TPM (PTP 1.07, clause 4.7, item 5) — gates the call, and a PCR is exempt from
/// dictionary-attack protection (Part 1, clause 14.7). The register's attributes may forbid the extend at the
/// command's locality (<c>TPM_RC_LOCALITY</c>).
/// </para>
/// <para>
/// Wire layout (Table 130): handle area <c>@pcrHandle</c> (TPMI_DH_PCR+); parameter <c>digests</c>
/// (TPML_DIGEST_VALUES). The command is <c>{NV}</c>. Its first parameter is a list, not a TPM2B, so no
/// parameter is encryptable.
/// </para>
/// <para>
/// See TPM 2.0 Library Part 3, clause 22.2, Table 130 - TPM2_PCR_Extend.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PcrExtendInput: ITpmCommandInput, IDisposable
{
    /// <summary>Whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PCR_Extend;

    /// <summary>
    /// The register to extend (<c>pcrHandle</c>, TPMI_DH_PCR+), or <c>TPM_RH_NULL</c> to validate the list and
    /// extend nothing.
    /// </summary>
    public TpmiDhPcr PcrHandle { get; }

    /// <summary>
    /// The tagged digests to extend, one per bank (<c>digests</c>, TPML_DIGEST_VALUES); owned by this input and
    /// released by <see cref="Dispose"/>.
    /// </summary>
    public TpmlDigestValues Digests { get; }

    /// <summary>
    /// Creates an input over an already-built digest list, adopting its ownership.
    /// </summary>
    /// <param name="pcrHandle">The register to extend, or <c>TPM_RH_NULL</c>.</param>
    /// <param name="digests">The tagged digests; ownership transfers to the returned input.</param>
    /// <returns>The command input.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="digests"/> is <see langword="null"/>.</exception>
    public static PcrExtendInput Create(TpmiDhPcr pcrHandle, TpmlDigestValues digests)
    {
        ArgumentNullException.ThrowIfNull(digests);

        return new PcrExtendInput(pcrHandle, digests);
    }

    /// <summary>
    /// Creates an input extending one bank with one digest — the common single-bank form.
    /// </summary>
    /// <param name="pcrHandle">The register to extend, or <c>TPM_RH_NULL</c>.</param>
    /// <param name="hashAlg">The bank's hash algorithm.</param>
    /// <param name="digest">The digest to extend, exactly the algorithm's width.</param>
    /// <param name="pool">The memory pool the digest carrier is rented from.</param>
    /// <returns>The command input.</returns>
    public static PcrExtendInput Create(TpmiDhPcr pcrHandle, TpmiAlgHash hashAlg, ReadOnlySpan<byte> digest, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmlDigestValues digests = TpmlDigestValues.Create(hashAlg, digest, pool);

        return new PcrExtendInput(pcrHandle, digests);
    }

    /// <summary>
    /// Initializes the input over an owned digest list.
    /// </summary>
    /// <param name="pcrHandle">The register to extend.</param>
    /// <param name="digests">The owned digest list.</param>
    private PcrExtendInput(TpmiDhPcr pcrHandle, TpmlDigestValues digests)
    {
        PcrHandle = pcrHandle;
        Digests = digests;
    }

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        return sizeof(uint) +               //pcrHandle (TPMI_DH_PCR+).
               Digests.GetSerializedSize(); //digests (TPML_DIGEST_VALUES).
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        PcrHandle.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(Disposed, this);

        Digests.WriteTo(ref writer);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            Digests.Dispose();
            Disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"PcrExtendInput(PcrHandle=0x{PcrHandle.Value:X8}, Digests={Digests.Count})";
}
