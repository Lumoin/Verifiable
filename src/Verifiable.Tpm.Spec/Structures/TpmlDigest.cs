using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPML_DIGEST - list of digests.
/// </summary>
/// <remarks>
/// <para>
/// This structure is returned by TPM2_PCR_Read containing the PCR values.
/// Each digest in the list corresponds to a selected PCR.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <list type="bullet">
///   <item><description>count (UINT32) - number of digests.</description></item>
///   <item><description>digests[count] (TPM2B_DIGEST) - array of digests.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.9.5, Table 123.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlDigest: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Initializes a new digest list.
    /// </summary>
    /// <param name="digests">The digests.</param>
    private TpmlDigest(List<Tpm2bDigest> digests)
    {
        this.Digests = digests;
    }

    /// <summary>
    /// Gets the number of digests.
    /// </summary>
    public int Count => Digests.Count;

    /// <summary>
    /// Gets the digest at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The digest.</returns>
    public Tpm2bDigest this[int index] => Digests[index];

    /// <summary>
    /// Gets all digests as a read-only list.
    /// </summary>
    public List<Tpm2bDigest> Digests { get; }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int size = sizeof(uint);
        foreach(var digest in Digests)
        {
            size += digest.SerializedSize;
        }

        return size;
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt32((uint)Digests.Count);

        foreach(var digest in Digests)
        {
            digest.WriteTo(ref writer);
        }
    }

    /// <summary>
    /// Parses a digest list from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed digest list.</returns>
    public static TpmlDigest Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        uint count = reader.ReadUInt32();

        //Each digest is a TPM2B_DIGEST occupying at least its 2-byte size prefix, so a count larger than the
        //remaining buffer can hold is a malformed length and must not size the backing list (Part 2, §10.9.5).
        reader.EnsureCount(count, sizeof(ushort));

        var digests = new List<Tpm2bDigest>((int)count);
        try
        {
            for(int i = 0; i < count; i++)
            {
                Tpm2bDigest digest = Tpm2bDigest.Parse(ref reader, pool);
                digests.Add(digest);
            }
        }
        catch
        {
            foreach(var parsed in digests)
            {
                parsed.Dispose();
            }

            throw;
        }

        return new TpmlDigest(digests);
    }

    /// <summary>
    /// Creates a digest list whose entries are copied into freshly rented pooled carriers, for a producer that
    /// holds the digest octets as spans rather than reading them off a wire reader.
    /// </summary>
    /// <remarks>
    /// The returned list owns every carrier it holds, so a caller transfers ownership by handing the list on and
    /// releases it by disposing the list. A rent that fails after earlier entries already succeeded releases
    /// those entries before the exception leaves, so a rejected construction orphans no pinned rental.
    /// </remarks>
    /// <param name="digests">The digest octets, in list order.</param>
    /// <param name="pool">The memory pool each entry's storage is rented from.</param>
    /// <returns>The created digest list.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="digests"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An entry is longer than <see cref="Tpm2bDigest.MaxSize"/>.</exception>
    public static TpmlDigest Create(IReadOnlyList<ReadOnlyMemory<byte>> digests, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(digests);
        ArgumentNullException.ThrowIfNull(pool);

        var carriers = new List<Tpm2bDigest>(digests.Count);
        try
        {
            for(int i = 0; i < digests.Count; i++)
            {
                carriers.Add(Tpm2bDigest.Create(digests[i].Span, pool));
            }
        }
        catch
        {
            foreach(var carrier in carriers)
            {
                carrier.Dispose();
            }

            throw;
        }

        return new TpmlDigest(carriers);
    }

    /// <summary>
    /// Releases resources owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            foreach(var digest in Digests)
            {
                digest.Dispose();
            }

            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPML_DIGEST({Count} digests)";
}
