using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Sized buffer containing an object Name (TPM2B_NAME).
/// </summary>
/// <remarks>
/// <para>
/// A Name is the unique identifier for an entity in the TPM. The format depends
/// on the entity type:
/// </para>
/// <list type="bullet">
///   <item><description><b>Permanent handles</b> (MSO = 0x40): Name = handle value (4 bytes).</description></item>
///   <item><description><b>NV indices</b> (MSO = 0x01): Name = nameAlg || H(TPMS_NV_PUBLIC).</description></item>
///   <item><description><b>Transient/persistent objects</b> (MSO = 0x80/0x81): Name = nameAlg || H(TPMT_PUBLIC).</description></item>
///   <item><description><b>PCRs</b> (MSO = 0x00): Name = handle value (4 bytes).</description></item>
/// </list>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of name in bytes.
///     BYTE name[size];                         // The Name data.
/// } TPM2B_NAME;
/// </code>
/// <para>
/// For objects, the Name starts with a 2-byte algorithm identifier (nameAlg)
/// followed by the hash digest. The total size is 2 + digestSize.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.5.3.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bName: IDisposable, ITpmWireType
{
    /// <summary>
    /// Maximum size of a Name (algorithm ID + largest digest).
    /// </summary>
    public const int MaxSize = 2 + 64; // sizeof(TPMI_ALG_HASH) + SHA-512 digest.

    private static readonly Tpm2bName EmptyInstance = new();

    private readonly IMemoryOwner<byte>? storage;
    private readonly int size;
    private bool disposed;

    /// <summary>
    /// Initializes an empty Name.
    /// </summary>
    private Tpm2bName()
    {
        storage = null;
        size = 0;
    }

    /// <summary>
    /// Initializes a new Name with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the Name bytes.</param>
    /// <param name="size">The actual length of the Name data.</param>
    private Tpm2bName(IMemoryOwner<byte> storage, int size)
    {
        this.storage = storage;
        this.size = size;
    }

    /// <summary>
    /// Gets an empty Name.
    /// </summary>
    public static Tpm2bName Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this Name is empty.
    /// </summary>
    public bool IsEmpty => size == 0;

    /// <summary>
    /// Gets the size of the Name in bytes.
    /// </summary>
    public int Size => size;

    /// <summary>
    /// Gets whether this is a handle-based Name (4 bytes, no algorithm prefix).
    /// </summary>
    public bool IsHandleName => size == 4;

    /// <summary>
    /// Gets whether this is a digest-based Name (algorithm prefix + hash).
    /// </summary>
    public bool IsDigestName => size > 4;

    /// <summary>
    /// Gets the Name data as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if(storage is null)
            {
                return [];
            }

            return storage.Memory.Span.Slice(0, size);
        }
    }

    /// <summary>
    /// Gets the name algorithm if this is a digest-based Name.
    /// </summary>
    public ushort NameAlgorithm
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(!IsDigestName)
            {
                return 0;
            }

            ReadOnlySpan<byte> span = Span;
            return (ushort)((span[0] << 8) | span[1]);
        }
    }

    /// <summary>
    /// Gets the digest portion if this is a digest-based Name.
    /// </summary>
    public ReadOnlySpan<byte> Digest
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(!IsDigestName)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return Span.Slice(2);
        }
    }

    /// <summary>
    /// Gets the handle value if this is a handle-based Name.
    /// </summary>
    public uint Handle
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(!IsHandleName)
            {
                return 0;
            }

            ReadOnlySpan<byte> span = Span;
            return (uint)((span[0] << 24) | (span[1] << 16) | (span[2] << 8) | span[3]);
        }
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + size;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)size);

        if(size > 0)
        {
            writer.WriteBytes(Span);
        }
    }

    /// <summary>
    /// Parses a Name from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed Name.</returns>
    public static Tpm2bName Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Name size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bName(storage, size);
    }

    /// <summary>
    /// Creates a Name from the specified bytes.
    /// </summary>
    /// <param name="bytes">The Name bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created Name.</returns>
    public static Tpm2bName Create(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Name too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bName(storage, bytes.Length);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            storage?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay
    {
        get
        {
            if(IsEmpty)
            {
                return "TPM2B_NAME(empty)";
            }

            if(IsHandleName)
            {
                return $"TPM2B_NAME(handle=0x{Handle:X8})";
            }

            return $"TPM2B_NAME(alg=0x{NameAlgorithm:X4}, {Digest.Length} bytes)";
        }
    }
}