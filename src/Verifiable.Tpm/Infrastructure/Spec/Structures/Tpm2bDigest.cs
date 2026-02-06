using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// TPM2B_DIGEST - a sized buffer for digest (hash) values.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds variable-length digest data prefixed with a 16-bit size field.
/// Digests are used for hash results, PCR values, cpHash/rpHash computations, and
/// random data from TPM2_GetRandom.
/// </para>
/// <para>
/// <strong>Wire format (big-endian):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the digest data.</description></item>
/// </list>
/// <para>
/// <strong>Common uses:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Hash results from TPM2_Hash.</description></item>
///   <item><description>PCR values from TPM2_PCR_Read.</description></item>
///   <item><description>Random bytes from TPM2_GetRandom.</description></item>
///   <item><description>cpHash and rpHash for session HMAC computation.</description></item>
/// </list>
/// <para>
/// <strong>Empty digests:</strong> Use <see cref="CreateEmpty"/> to obtain a shared
/// empty instance backed by <see cref="EmptyMemoryOwner"/>. This avoids pool allocations
/// for zero-length buffers.
/// </para>
/// <para>
/// See TPM 2.0 Part 2, Section 10.4.2.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bDigest: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static readonly Tpm2bDigest EmptyInstance = new(Cryptography.EmptyMemoryOwner.Instance);

    /// <summary>
    /// Gets an empty digest.
    /// </summary>
    public static Tpm2bDigest Empty => EmptyInstance;

    /// <summary>
    /// Initializes a new digest with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the digest bytes.</param>
    public Tpm2bDigest(IMemoryOwner<byte> storage): base(storage, TpmTags.Digest)
    {
    }

    /// <summary>
    /// Gets the size of the digest data in bytes.
    /// </summary>
    public int Size => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets a value indicating whether this digest is empty.
    /// </summary>
    public bool IsEmpty => Size == 0;

    /// <summary>
    /// Parses a digest from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the digest.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed digest.</returns>
    public static Tpm2bDigest Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();
        if(size == 0)
        {
            return EmptyInstance;
        }

        IMemoryOwner<byte> storage = pool.Rent(size);

        //Copy digest bytes into owned storage.
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(size);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bDigest(storage);
    }

    /// <summary>
    /// Writes this digest to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Gets the serialized size (2-byte size prefix + data).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Size;

    /// <summary>
    /// Creates a digest from the specified bytes.
    /// </summary>
    /// <param name="bytes">The digest bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created digest.</returns>
    public static Tpm2bDigest Create(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);
        return new Tpm2bDigest(storage);
    }

    private string DebuggerDisplay => $"TPM2B_DIGEST({Size} bytes)";
}