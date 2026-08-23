using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Hash-agile digest structure (TPMT_HA): a hash algorithm selector followed by a digest whose length the
/// selector implies.
/// </summary>
/// <remarks>
/// <para>
/// Unlike a TPM2B carrier, the digest carries no explicit size field on the wire — its length follows from
/// <see cref="HashAlg"/> (<see cref="TpmiAlgHash.DigestSize"/>). When <see cref="HashAlg"/> is
/// <c>TPM_ALG_NULL</c>, no digest octets are transmitted at all.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     +TPMI_ALG_HASH hashAlg;                  // Selector of the hash contained in the digest.
///     TPMU_HA        digest;                   // The digest data, sized by hashAlg.
/// } TPMT_HA;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.3.2, Table 91.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmtHa: IDisposable, ITpmWireType
{
    private static TpmtHa NullInstance { get; } = new(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_NULL), null, 0);

    private IMemoryOwner<byte>? Storage { get; }
    private bool disposed;

    /// <summary>
    /// Gets the hash algorithm selector, which implies the digest length.
    /// </summary>
    public TpmiAlgHash HashAlg { get; }

    /// <summary>
    /// Gets the digest length in octets.
    /// </summary>
    public int Size { get; }

    /// <summary>
    /// Initializes a new hash-agile digest with the specified storage.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm selector.</param>
    /// <param name="storage">The memory owner containing the digest bytes, or <see langword="null"/> for the NULL algorithm.</param>
    /// <param name="size">The digest length in octets.</param>
    private TpmtHa(TpmiAlgHash hashAlg, IMemoryOwner<byte>? storage, int size)
    {
        HashAlg = hashAlg;
        this.Storage = storage;
        Size = size;
    }

    /// <summary>
    /// Gets the NULL hash-agile digest (<c>hashAlg == TPM_ALG_NULL</c>, no digest octets).
    /// </summary>
    public static TpmtHa Null => NullInstance;

    /// <summary>
    /// Gets whether this is the NULL hash-agile digest.
    /// </summary>
    public bool IsNull => HashAlg.IsNull;

    /// <summary>
    /// Gets the digest as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Digest
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if(Storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return Storage.Memory.Span.Slice(0, Size);
        }
    }

    /// <summary>
    /// Gets the digest as read-only memory that aliases this instance's pooled storage — for a borrowing
    /// consumer, valid until <see cref="Dispose"/> and never copied into an untracked array.
    /// </summary>
    /// <returns>The digest bytes.</returns>
    public ReadOnlyMemory<byte> AsReadOnlyMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if(Storage is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return Storage.Memory.Slice(0, Size);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Size;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        HashAlg.WriteTo(ref writer);

        if(Size > 0)
        {
            writer.WriteBytes(Digest);
        }
    }

    /// <summary>
    /// Parses a hash-agile digest from a TPM reader. The digest length follows from the parsed
    /// <see cref="HashAlg"/>; no explicit size field is present on the wire.
    /// </summary>
    /// <param name="reader">The reader positioned at <c>hashAlg</c>.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <param name="isNullAdmitted">Whether <c>hashAlg</c> may be <c>TPM_ALG_NULL</c>.</param>
    /// <returns>The parsed structure.</returns>
    /// <exception cref="InvalidOperationException"><c>hashAlg</c> is not an admitted hash algorithm (<c>TPM_RC_HASH</c>).</exception>
    public static TpmtHa Parse(ref TpmReader reader, BaseMemoryPool pool, bool isNullAdmitted = false)
    {
        ArgumentNullException.ThrowIfNull(pool);
        TpmiAlgHash hashAlg = TpmiAlgHash.Parse(ref reader, isNullAdmitted);

        if(hashAlg.IsNull)
        {
            return Null;
        }

        int size = hashAlg.DigestSize!.Value;
        IMemoryOwner<byte> storage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span.Slice(0, size));

        return new TpmtHa(hashAlg, storage, size);
    }

    /// <summary>
    /// Creates a hash-agile digest from an algorithm and its digest bytes.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm selector.</param>
    /// <param name="digest">
    /// The digest bytes; must be empty for <c>TPM_ALG_NULL</c> and exactly <see cref="TpmiAlgHash.DigestSize"/>
    /// octets for any other algorithm.
    /// </param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created structure.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="hashAlg"/> has no known digest size, or <paramref name="digest"/> does not match it.
    /// </exception>
    public static TpmtHa Create(TpmiAlgHash hashAlg, ReadOnlySpan<byte> digest, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(hashAlg.IsNull)
        {
            if(!digest.IsEmpty)
            {
                throw new ArgumentException("A TPM_ALG_NULL hash algorithm carries no digest octets.", nameof(digest));
            }

            return Null;
        }

        int? expectedSize = hashAlg.DigestSize;
        if(expectedSize is null)
        {
            throw new ArgumentException($"'{hashAlg.Value}' is not a hash algorithm with a known digest size.", nameof(hashAlg));
        }

        if(digest.Length != expectedSize.Value)
        {
            throw new ArgumentException($"Digest length {digest.Length} does not match the {expectedSize.Value}-octet digest size of '{hashAlg.Value}'.", nameof(digest));
        }

        IMemoryOwner<byte> storage = pool.Rent(expectedSize.Value);
        digest.CopyTo(storage.Memory.Span);

        return new TpmtHa(hashAlg, storage, expectedSize.Value);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != NullInstance)
        {
            Storage?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => IsNull ? "TPMT_HA(NULL)" : $"TPMT_HA({HashAlg.Value}, {Size} bytes)";
}
