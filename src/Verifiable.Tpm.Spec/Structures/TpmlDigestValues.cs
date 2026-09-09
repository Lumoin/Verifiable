using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Tpm.Spec.Algorithms;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// List of tagged digests (TPML_DIGEST_VALUES): the digests <c>TPM2_PCR_Event()</c> and
/// <c>TPM2_EventSequenceComplete()</c> return, one per implemented hash algorithm, and the digests
/// <c>TPM2_PCR_Extend()</c> takes, one per bank to extend.
/// </summary>
/// <remarks>
/// <para>
/// Each entry is a <see cref="TpmtHa"/> — a hash algorithm followed by a digest of exactly that algorithm's
/// width, with no size field of its own — so the list's own count is the only length information on the wire.
/// Part 2, clause 10.8.6: "This construct limits the number of hashes in the list to the number of digests
/// implemented in the TPM rather than the number of PCR banks. This allows extra values to appear in a call to
/// TPM2_PCR_Extend()."
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <list type="bullet">
///   <item><description>count (UINT32) - number of digests, at most <c>HASH_COUNT</c> (<c>#TPM_RC_SIZE</c>).</description></item>
///   <item><description>digests[count] (TPMT_HA) - the tagged digests.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.8.6, Table 127.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmlDigestValues: ITpmWireType, IDisposable
{
    /// <summary>
    /// The bound on <c>count</c>: Table 127's <c>{:HASH_COUNT}</c>, rendered with the same library constant
    /// <see cref="TpmlPcrSelection.MaxSelections"/> renders Table 128's <c>{:HASH_COUNT}</c> with — the two
    /// lists are bounded by one Part 2 constant. A TPM applies its own implemented-hash count, which is never
    /// larger.
    /// </summary>
    public const int MaxDigests = TpmlPcrSelection.MaxSelections;

    /// <summary>
    /// The shared zero-entry instance: a <c>TPM2_PCR_Extend()</c> with no digest at all extends nothing
    /// (Part 3, clause 22.2.1: "If no digest value is specified for a bank, then the PCR in that bank is not
    /// modified").
    /// </summary>
    private static TpmlDigestValues EmptyInstance { get; } = new([]);

    /// <summary>
    /// Whether <see cref="Dispose"/> has already released the entries.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Initializes a list over already-built entries whose ownership transfers to this instance.
    /// </summary>
    /// <param name="digests">The owned entries, in list order.</param>
    private TpmlDigestValues(List<TpmtHa> digests)
    {
        Digests = digests;
    }

    /// <summary>
    /// Gets the shared zero-entry list. It owns nothing and its <see cref="Dispose"/> is a no-op.
    /// </summary>
    public static TpmlDigestValues Empty => EmptyInstance;

    /// <summary>
    /// Gets the number of digests.
    /// </summary>
    public int Count => Digests.Count;

    /// <summary>
    /// Gets the digest at the specified index.
    /// </summary>
    /// <param name="index">The index.</param>
    /// <returns>The tagged digest.</returns>
    public TpmtHa this[int index] => Digests[index];

    /// <summary>
    /// Gets the tagged digests in list order; each is owned by this list.
    /// </summary>
    public IReadOnlyList<TpmtHa> Digests { get; }

    /// <summary>
    /// Gets the serialized size of this structure: the <c>UINT32</c> count and each entry's algorithm
    /// identifier plus digest.
    /// </summary>
    /// <returns>The serialized size in octets.</returns>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int size = sizeof(uint);
        foreach(TpmtHa digest in Digests)
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

        foreach(TpmtHa digest in Digests)
        {
            digest.WriteTo(ref writer);
        }
    }

    /// <summary>
    /// Parses a tagged-digest list from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The count bound is checked before any entry is rented, so a malformed list never leaves a pinned rental
    /// behind; an entry whose <c>hashAlg</c> is not a hash algorithm raises <see cref="TpmtHa.Parse"/>'s own
    /// <see cref="InvalidOperationException"/> (<c>TPM_RC_HASH</c>), after which every already-parsed entry is
    /// released.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool each entry's storage is rented from.</param>
    /// <returns>The parsed list.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">The list holds more than <see cref="MaxDigests"/> entries (<c>TPM_RC_SIZE</c>), or an entry's <c>hashAlg</c> is not a hash algorithm (<c>TPM_RC_HASH</c>).</exception>
    public static TpmlDigestValues Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        uint count = reader.ReadUInt32();

        if(count == 0)
        {
            return Empty;
        }

        if(count > MaxDigests)
        {
            throw new InvalidOperationException($"Digest list count {count} exceeds maximum {MaxDigests}.");
        }

        //Each entry carries at least its 2-octet algorithm identifier, so a count the remaining octets cannot
        //hold is a malformed length and must not size the backing list.
        reader.EnsureCount(count, sizeof(ushort));

        var digests = new List<TpmtHa>((int)count);
        try
        {
            for(int i = 0; i < count; i++)
            {
                digests.Add(TpmtHa.Parse(ref reader, pool));
            }
        }
        catch
        {
            foreach(TpmtHa parsed in digests)
            {
                parsed.Dispose();
            }

            throw;
        }

        return new TpmlDigestValues(digests);
    }

    /// <summary>
    /// Adopts a caller-assembled list of already-built tagged digests as this structure's storage: ownership of
    /// every entry transfers to the returned instance with no re-copy — the way a producer that builds one
    /// <see cref="TpmtHa"/> per implemented hash algorithm assembles the response list.
    /// </summary>
    /// <remarks>
    /// Ownership of every entry in <paramref name="digests"/> transfers to this call regardless of outcome: on
    /// success the returned instance owns them all; a <see langword="null"/> entry disposes every non-null
    /// entry before the exception leaves, so a rejected adoption never orphans a pinned rental. An empty input
    /// yields <see cref="Empty"/>.
    /// </remarks>
    /// <param name="digests">The already-built tagged digests, in list order; ownership of each transfers to this call.</param>
    /// <returns>The adopted list.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="digests"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">An entry is <see langword="null"/>, or the list holds more than <see cref="MaxDigests"/> entries.</exception>
    public static TpmlDigestValues Adopt(IReadOnlyList<TpmtHa> digests)
    {
        ArgumentNullException.ThrowIfNull(digests);

        bool isRejected = digests.Count > MaxDigests;
        for(int i = 0; i < digests.Count && !isRejected; i++)
        {
            isRejected = digests[i] is null;
        }

        if(isRejected)
        {
            for(int i = 0; i < digests.Count; i++)
            {
                digests[i]?.Dispose();
            }

            throw new ArgumentException($"A TPML_DIGEST_VALUES holds at most {MaxDigests} non-null entries.", nameof(digests));
        }

        if(digests.Count == 0)
        {
            return Empty;
        }

        return new TpmlDigestValues([.. digests]);
    }

    /// <summary>
    /// Creates a one-entry list from an algorithm and its digest octets — the common <c>TPM2_PCR_Extend()</c>
    /// input extending a single bank.
    /// </summary>
    /// <param name="hashAlg">The bank's hash algorithm.</param>
    /// <param name="digest">The digest to extend, exactly the algorithm's width.</param>
    /// <param name="pool">The memory pool the entry's storage is rented from.</param>
    /// <returns>The created list; the caller owns it.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="hashAlg"/> has no known digest size, or <paramref name="digest"/> does not match it.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the built TPMT_HA entry transfers to the returned list, whose Dispose releases it.")]
    public static TpmlDigestValues Create(TpmiAlgHash hashAlg, ReadOnlySpan<byte> digest, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        TpmtHa entry = TpmtHa.Create(hashAlg, digest, pool);

        return new TpmlDigestValues([entry]);
    }

    /// <summary>
    /// Releases every owned entry. Repeated calls and calls on <see cref="Empty"/> do nothing.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            foreach(TpmtHa digest in Digests)
            {
                digest.Dispose();
            }

            disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the entry count only.
    /// </summary>
    private string DebuggerDisplay => $"TPML_DIGEST_VALUES({Digests.Count} digests)";
}
