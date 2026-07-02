using System;
using System.Collections.Immutable;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Automata;

/// <summary>
/// The durable state of one Platform Configuration Register bank: the registers of a single hash algorithm,
/// each holding the current measurement digest (TPM 2.0 Library Part 1, clause 17.1). <c>TPM2_PCR_Read()</c>
/// returns the selected registers' values and <c>TPM2_Quote()</c> signs a digest computed over them, so the
/// bank is carried as durable automaton state alongside the loaded objects and NV Indexes.
/// </summary>
/// <remarks>
/// <para>
/// <b>Modelled scope (current).</b> Only the SHA-256 bank is modelled, initialized to its reset image at
/// power-on. This slice models no <c>TPM2_PCR_Extend()</c>, so the registers never change after reset; a later
/// slice adds extend (advancing the values and a PCR update counter) and <c>TPM2_PolicyPCR()</c>. Because a
/// value is only ever replaced wholesale (never mutated in place), it is held as an immutable
/// <see cref="ReadOnlyMemory{T}"/> exactly as the other durable model state is.
/// </para>
/// <para>
/// <b>Reset image (simplification).</b> All registers are modelled as the all-zero reset value. A conformant
/// TPM resets PCR[0..16] and PCR[23] to all-zero on a TPM Reset but resets the DRTM/locality registers
/// PCR[17..22] to all-one (TPM 2.0 Library Part 1, clause 17.5.3); that distinction is not drawn here because
/// no command in this slice reads those registers, and <c>TPM2_Quote()</c> hashes the exact same bank values
/// <c>TPM2_PCR_Read()</c> returns, so the attested composite and the recomputed composite agree regardless.
/// </para>
/// </remarks>
/// <param name="HashAlgorithm">The bank's hash algorithm (<c>TPM_ALG_SHA256</c> this slice).</param>
/// <param name="Values">The register values, indexed by PCR number; each is the bank digest width.</param>
public sealed record PcrBankState(TpmAlgIdConstants HashAlgorithm, ImmutableArray<ReadOnlyMemory<byte>> Values)
{
    /// <summary>The number of Platform Configuration Registers in a bank (PCR[0..23]).</summary>
    public const int PcrCount = 24;

    /// <summary>The width in octets of a SHA-256 PCR value.</summary>
    public const int Sha256DigestSize = 32;

    /// <summary>
    /// Creates the SHA-256 bank at its reset image: every register the all-zero value (see the remarks on
    /// <see cref="PcrBankState"/> for the reset-image simplification).
    /// </summary>
    /// <returns>A freshly reset SHA-256 bank.</returns>
    public static PcrBankState Sha256AtReset()
    {
        ImmutableArray<ReadOnlyMemory<byte>>.Builder builder = ImmutableArray.CreateBuilder<ReadOnlyMemory<byte>>(PcrCount);
        for(int i = 0; i < PcrCount; i++)
        {
            builder.Add(new byte[Sha256DigestSize]);
        }

        return new PcrBankState(TpmAlgIdConstants.TPM_ALG_SHA256, builder.MoveToImmutable());
    }
}
