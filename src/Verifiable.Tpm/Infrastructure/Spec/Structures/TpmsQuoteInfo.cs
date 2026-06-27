using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Quote-specific attestation information (TPMS_QUOTE_INFO), the <c>quote</c> member of TPMU_ATTEST.
/// </summary>
/// <remarks>
/// <para>
/// Binds a quote to a selected set of PCRs (<see cref="PcrSelect"/>) and the digest the TPM computed over
/// their values (<see cref="PcrDigest"/>). A verifier reads the same PCRs, recomputes the composite digest as
/// the hash of the concatenation of the selected PCR values in selection order, and compares it to
/// <see cref="PcrDigest"/> (TPM 2.0 Library Part 4, <c>PCRComputeCurrentDigest</c>).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPML_PCR_SELECTION pcrSelect;            // Information on algID, PCR selected and digest.
///     TPM2B_DIGEST       pcrDigest;            // Digest of the selected PCR using the hash of the signing scheme.
/// } TPMS_QUOTE_INFO;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.12.1, Table 167.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsQuoteInfo: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the PCR selection the quote covers.
    /// </summary>
    public TpmlPcrSelection PcrSelect { get; }

    /// <summary>
    /// Gets the digest the TPM computed over the selected PCR values.
    /// </summary>
    public Tpm2bDigest PcrDigest { get; }

    /// <summary>
    /// Initializes a new quote-info structure.
    /// </summary>
    /// <param name="pcrSelect">The PCR selection. Ownership is transferred.</param>
    /// <param name="pcrDigest">The PCR composite digest. Ownership is transferred.</param>
    private TpmsQuoteInfo(TpmlPcrSelection pcrSelect, Tpm2bDigest pcrDigest)
    {
        PcrSelect = pcrSelect;
        PcrDigest = pcrDigest;
    }

    /// <summary>
    /// Creates a quote-info structure from a selection and digest (for tests and round-trips).
    /// </summary>
    /// <param name="pcrSelect">The PCR selection. Ownership is transferred.</param>
    /// <param name="pcrDigest">The PCR composite digest. Ownership is transferred.</param>
    /// <returns>The created quote info.</returns>
    public static TpmsQuoteInfo Create(TpmlPcrSelection pcrSelect, Tpm2bDigest pcrDigest)
    {
        ArgumentNullException.ThrowIfNull(pcrSelect);
        ArgumentNullException.ThrowIfNull(pcrDigest);

        return new TpmsQuoteInfo(pcrSelect, pcrDigest);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return PcrSelect.GetSerializedSize() + PcrDigest.SerializedSize;
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        PcrSelect.WriteTo(ref writer);
        PcrDigest.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a quote-info structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed quote info.</returns>
    public static TpmsQuoteInfo Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        TpmlPcrSelection pcrSelect = TpmlPcrSelection.Parse(ref reader, pool);
        Tpm2bDigest pcrDigest = Tpm2bDigest.Parse(ref reader, pool);

        return new TpmsQuoteInfo(pcrSelect, pcrDigest);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            PcrSelect.Dispose();
            PcrDigest.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_QUOTE_INFO({PcrSelect.Count} selections, pcrDigest={PcrDigest.Size} bytes)";
}
