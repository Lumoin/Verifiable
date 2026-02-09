using System;
using System.Buffers;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_PCR_Read command.
/// </summary>
/// <remarks>
/// <para>
/// TPM2_PCR_Read reads the current values of the specified PCRs.
/// This command has no handles - only parameters.
/// </para>
/// <para>
/// <b>Command parameters:</b>
/// </para>
/// <list type="bullet">
///   <item><description>pcrSelectionIn (TPML_PCR_SELECTION) - PCRs to read.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 3, Section 22.4.
/// </para>
/// </remarks>
public sealed class PcrReadInput: ITpmCommandInput, IDisposable
{
    private readonly TpmlPcrSelection pcrSelection;
    private bool disposed;

    /// <summary>
    /// Initializes a new PCR_Read input.
    /// </summary>
    /// <param name="pcrSelection">The PCR selection. Ownership is transferred.</param>
    private PcrReadInput(TpmlPcrSelection pcrSelection)
    {
        this.pcrSelection = pcrSelection;
    }

    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_PCR_Read;

    /// <inheritdoc/>
    public int GetSerializedSize()
    {
        //No handles, only parameters.
        return pcrSelection.GetSerializedSize();
    }

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //No handles for PCR_Read.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        pcrSelection.WriteTo(ref writer);
    }

    /// <summary>
    /// Creates input from an existing PCR selection.
    /// </summary>
    /// <param name="pcrSelection">The PCR selection. Ownership is transferred.</param>
    /// <returns>The input.</returns>
    public static PcrReadInput FromSelection(TpmlPcrSelection pcrSelection)
    {
        return new PcrReadInput(pcrSelection);
    }

    /// <summary>
    /// Creates input to read specific PCRs from a single bank.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm (bank).</param>
    /// <param name="pcrIndices">The PCR indices to read (0-23).</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The input.</returns>
    public static PcrReadInput ForPcrs(TpmAlgIdConstants hashAlg, ReadOnlySpan<int> pcrIndices, MemoryPool<byte> pool)
    {
        TpmlPcrSelection selection = TpmlPcrSelection.Create(hashAlg, pcrIndices, pool);
        return new PcrReadInput(selection);
    }

    /// <summary>
    /// Creates input to read all PCRs (0-23) from a single bank.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm (bank).</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The input.</returns>
    public static PcrReadInput ForAllPcrs(TpmAlgIdConstants hashAlg, MemoryPool<byte> pool)
    {
        Span<int> allPcrs = stackalloc int[24];
        for(int i = 0; i < 24; i++)
        {
            allPcrs[i] = i;
        }

        return ForPcrs(hashAlg, allPcrs, pool);
    }

    /// <summary>
    /// Creates input to read boot-related PCRs (0-7) from a specified bank.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm (bank).</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The input.</returns>
    public static PcrReadInput ForBootPcrs(TpmAlgIdConstants hashAlg, MemoryPool<byte> pool)
    {
        Span<int> bootPcrs = stackalloc int[] { 0, 1, 2, 3, 4, 5, 6, 7 };
        return ForPcrs(hashAlg, bootPcrs, pool);
    }

    /// <summary>
    /// Releases resources owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            pcrSelection.Dispose();
            disposed = true;
        }
    }
}