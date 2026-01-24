using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

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
/// Specification reference: TPM 2.0 Library Part 2, Section 10.5.2.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlDigest: IDisposable
{
    private readonly List<Tpm2bDigest> digests;
    private bool disposed;

    /// <summary>
    /// Initializes a new digest list.
    /// </summary>
    /// <param name="digests">The digests.</param>
    private TpmlDigest(List<Tpm2bDigest> digests)
    {
        this.digests = digests;
    }

    /// <summary>
    /// Gets the number of digests.
    /// </summary>
    public int Count => digests.Count;

    /// <summary>
    /// Gets the digest at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The digest.</returns>
    public Tpm2bDigest this[int index] => digests[index];

    /// <summary>
    /// Gets all digests as a read-only list.
    /// </summary>
    public IReadOnlyList<Tpm2bDigest> Digests => digests;

    /// <summary>
    /// Parses a digest list from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The parsed digest list.</returns>
    public static TpmlDigest Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        uint count = reader.ReadUInt32();
        var digests = new List<Tpm2bDigest>((int)count);

        for(int i = 0; i < count; i++)
        {
            Tpm2bDigest digest = Tpm2bDigest.Parse(ref reader, pool);
            digests.Add(digest);
        }

        return new TpmlDigest(digests);
    }

    /// <summary>
    /// Releases resources owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            foreach(var digest in digests)
            {
                digest.Dispose();
            }

            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPML_DIGEST({Count} digests)";
}