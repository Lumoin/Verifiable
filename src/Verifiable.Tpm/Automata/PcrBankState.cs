using System;
using System.Collections.Immutable;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The durable state of one Platform Configuration Register bank: the registers of a single hash algorithm,
/// each holding the current measurement digest (TPM 2.0 Library Part 1, clause 14 (PCR Operations)).
/// <c>TPM2_PCR_Extend()</c>, <c>TPM2_PCR_Event()</c> and <c>TPM2_EventSequenceComplete()</c> advance a register
/// by <c>PCRnew = H(PCRold ‖ digest)</c> (clause 14.2, equation 13), <c>TPM2_PCR_Reset()</c> and
/// <c>TPM2_Startup()</c> return one to its reset image (clause 14.1), <c>TPM2_PCR_Read()</c> returns the
/// selected values and <c>TPM2_Quote()</c> signs a digest computed over them, so the bank is carried as durable
/// automaton state alongside the loaded objects and NV Indexes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Modelled scope.</b> Only the SHA-256 bank is modelled, with every one of its 24 registers allocated
/// (PTP 1.07, clause 3.6: a PC Client TPM implements PCR 0–23 in each allocated bank). A digest tagged for any
/// other bank is accepted by the extending commands and ignored, exactly as Part 3, clause 22.2.1 has it for a
/// bank the TPM does not implement. Because a value is only ever replaced wholesale (never mutated in place),
/// each register is held as an immutable <see cref="ReadOnlyMemory{T}"/> over an array — durable model state
/// with the simulator's own lifetime and no owner to release, the same representation the reset image has had
/// since the bank was first modelled; a pooled register image is a structural candidate, not this type's.
/// </para>
/// <para>
/// <b>Reset image.</b> <see cref="Sha256AtReset"/> renders PTP 1.07 Table 15 for a <c>TPM2_Startup(CLEAR)</c>
/// with no S-HCRTM sequence: PCR 0 the locality indicator (0 at locality 0), PCR 1–16 and 23 all zeros, and the
/// D-RTM registers 17–22 −1 — all ones (<see cref="PcClientPcrAttributes.HasAllOnesResetImage"/>). A register
/// <c>TPM2_PCR_Reset()</c> resets goes to all zeros regardless (Table 15's "TPM2_PCR_Reset" column; Part 4
/// <c>PCRSetValue(handle, 0)</c>).
/// </para>
/// </remarks>
/// <param name="HashAlgorithm">The bank's hash algorithm (<c>TPM_ALG_SHA256</c>).</param>
/// <param name="Values">The register values, indexed by PCR number; each is the bank digest width.</param>
public sealed record PcrBankState(TpmAlgIdConstants HashAlgorithm, ImmutableArray<ReadOnlyMemory<byte>> Values)
{
    /// <summary>The number of Platform Configuration Registers in a bank (PCR[0..23]).</summary>
    public const int PcrCount = 24;

    /// <summary>The width in octets of a SHA-256 PCR value.</summary>
    public const int Sha256DigestSize = 32;

    /// <summary>
    /// Creates the SHA-256 bank at its reset image (PTP 1.07 Table 15; see the remarks on
    /// <see cref="PcrBankState"/>).
    /// </summary>
    /// <returns>A freshly reset SHA-256 bank.</returns>
    public static PcrBankState Sha256AtReset()
    {
        ImmutableArray<ReadOnlyMemory<byte>>.Builder builder = ImmutableArray.CreateBuilder<ReadOnlyMemory<byte>>(PcrCount);
        for(int pcr = 0; pcr < PcrCount; pcr++)
        {
            builder.Add(ResetImage(pcr));
        }

        return new PcrBankState(TpmAlgIdConstants.TPM_ALG_SHA256, builder.MoveToImmutable());
    }

    /// <summary>
    /// Replaces one register with its extended value — the result of <c>H(PCRold ‖ digest)</c> the extending
    /// command's effect computed (TPM 2.0 Library Part 1, clause 14.2, equation 13).
    /// </summary>
    /// <param name="pcr">The register index.</param>
    /// <param name="extendedValue">The new register value, exactly the bank's digest width.</param>
    /// <returns>The bank with the register replaced.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="pcr"/> is not a register of this bank.</exception>
    /// <exception cref="ArgumentException"><paramref name="extendedValue"/> is not the bank's digest width.</exception>
    public PcrBankState Extend(int pcr, ReadOnlyMemory<byte> extendedValue)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(pcr);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(pcr, PcrCount);

        if(extendedValue.Length != Sha256DigestSize)
        {
            throw new ArgumentException($"A SHA-256 register value is {Sha256DigestSize} octets; got {extendedValue.Length}.", nameof(extendedValue));
        }

        return this with { Values = Values.SetItem(pcr, extendedValue) };
    }

    /// <summary>
    /// Returns one register to all zeros — <c>TPM2_PCR_Reset()</c>'s effect on a resettable register (TPM 2.0
    /// Library Part 3, clause 22.8.1: "set the PCR in all banks to zero"; PTP 1.07 Table 15's "TPM2_PCR_Reset"
    /// column). Whether the register may be reset at all is the caller's gate
    /// (<see cref="PcClientPcrAttributes.IsResetAllowedAtLocalityZero"/>).
    /// </summary>
    /// <param name="pcr">The register index.</param>
    /// <returns>The bank with the register zeroed.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="pcr"/> is not a register of this bank.</exception>
    public PcrBankState ResetRegister(int pcr)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(pcr);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(pcr, PcrCount);

        return this with { Values = Values.SetItem(pcr, new byte[Sha256DigestSize]) };
    }

    /// <summary>
    /// Applies <c>TPM2_Startup()</c>'s rule to the bank (TPM 2.0 Library Part 1, clause 14.1): a TPM Reset or
    /// TPM Restart returns every register to its reset image; a TPM Resume carries forward the registers
    /// <c>TPM_PT_PCR_SAVE</c> preserves (PCR 0–15, <see cref="PcClientPcrAttributes.IsPreservedByResume"/>) and
    /// returns the rest to their reset image (Part 4 <c>PCRStartup</c>). The simulator keeps its registers live
    /// across <c>TPM2_Shutdown(STATE)</c>, so "restored to the state they had at the last Shutdown(STATE)" is
    /// "left as they are".
    /// </summary>
    /// <param name="isResume">Whether the Startup is a TPM Resume; otherwise a Reset or Restart.</param>
    /// <returns>The bank after the Startup.</returns>
    public PcrBankState AtStartup(bool isResume)
    {
        if(!isResume)
        {
            return Sha256AtReset();
        }

        ImmutableArray<ReadOnlyMemory<byte>>.Builder builder = Values.ToBuilder();
        for(int pcr = 0; pcr < PcrCount; pcr++)
        {
            if(!PcClientPcrAttributes.IsPreservedByResume(pcr))
            {
                builder[pcr] = ResetImage(pcr);
            }
        }

        return this with { Values = builder.MoveToImmutable() };
    }

    /// <summary>
    /// The reset image of one register (PTP 1.07 Table 15): all ones for the D-RTM registers, all zeros
    /// otherwise.
    /// </summary>
    /// <param name="pcr">The register index.</param>
    /// <returns>A fresh register value.</returns>
    private static ReadOnlyMemory<byte> ResetImage(int pcr)
    {
        byte[] image = new byte[Sha256DigestSize];
        if(PcClientPcrAttributes.HasAllOnesResetImage(pcr))
        {
            image.AsSpan().Fill(0xFF);
        }

        return image;
    }
}
