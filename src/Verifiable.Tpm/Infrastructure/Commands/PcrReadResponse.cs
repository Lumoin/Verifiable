using System;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_PCR_Read.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response parameter area for the
/// TPM2_PCR_Read command. It bundles the individual response parameters
/// as defined in the specification.
/// </para>
/// <para>
/// <b>Response parameters (Part 3, Section 22.4):</b>
/// </para>
/// <list type="bullet">
///   <item><description>pcrUpdateCounter (UINT32) - current value of the PCR update counter.</description></item>
///   <item><description>pcrSelectionOut (TPML_PCR_SELECTION) - the PCRs in the returned list.</description></item>
///   <item><description>pcrValues (TPML_DIGEST) - the contents of the PCRs.</description></item>
/// </list>
/// <para>
/// <b>Note:</b> This is a library convenience type that bundles the response
/// parameters. The TPM specification defines these as separate parameters in
/// the response, not as a named structure.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class PcrReadResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the PCR update counter.
    /// </summary>
    /// <remarks>
    /// This counter increments each time a PCR is extended. It can be used
    /// to detect if PCRs have changed between reads.
    /// </remarks>
    public uint PcrUpdateCounter { get; }

    /// <summary>
    /// Gets the PCR selection indicating which PCRs were returned.
    /// </summary>
    /// <remarks>
    /// The TPM may return fewer PCRs than requested if the response would
    /// exceed the maximum response size. Compare this with the requested
    /// selection to determine if additional reads are needed.
    /// </remarks>
    public TpmlPcrSelection PcrSelectionOut { get; }

    /// <summary>
    /// Gets the PCR values.
    /// </summary>
    /// <remarks>
    /// The digests are in the same order as the PCRs indicated in
    /// <see cref="PcrSelectionOut"/>.
    /// </remarks>
    public TpmlDigest PcrValues { get; }

    private PcrReadResponse(uint pcrUpdateCounter, TpmlPcrSelection pcrSelectionOut, TpmlDigest pcrValues)
    {
        PcrUpdateCounter = pcrUpdateCounter;
        PcrSelectionOut = pcrSelectionOut;
        PcrValues = pcrValues;
    }

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static PcrReadResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        uint pcrUpdateCounter = reader.ReadUInt32();
        TpmlPcrSelection pcrSelectionOut = TpmlPcrSelection.Parse(ref reader, pool);
        TpmlDigest pcrValues = TpmlDigest.Parse(ref reader, pool);

        return new PcrReadResponse(pcrUpdateCounter, pcrSelectionOut, pcrValues);
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            PcrSelectionOut.Dispose();
            PcrValues.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"PcrReadResponse(Counter={PcrUpdateCounter}, {PcrValues.Count} values)";
}