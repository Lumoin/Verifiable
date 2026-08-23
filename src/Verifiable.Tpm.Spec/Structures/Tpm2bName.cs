using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

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

    private static Tpm2bName EmptyInstance { get; } = new();

    private IMemoryOwner<byte>? Storage { get; }
    private bool disposed;

    /// <summary>
    /// Initializes an empty Name.
    /// </summary>
    private Tpm2bName()
    {
        Storage = null;
        Size = 0;
    }

    /// <summary>
    /// Initializes a new Name with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the Name bytes.</param>
    /// <param name="size">The actual length of the Name data.</param>
    private Tpm2bName(IMemoryOwner<byte> storage, int size)
    {
        this.Storage = storage;
        this.Size = size;
    }

    /// <summary>
    /// Gets an empty Name.
    /// </summary>
    public static Tpm2bName Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this Name is empty.
    /// </summary>
    public bool IsEmpty => Size == 0;

    /// <summary>
    /// Gets the size of the Name in bytes.
    /// </summary>
    public int Size { get; }

    /// <summary>
    /// Gets whether this is a handle-based Name (4 bytes, no algorithm prefix).
    /// </summary>
    public bool IsHandleName => Size == 4;

    /// <summary>
    /// Gets whether this is a digest-based Name (algorithm prefix + hash).
    /// </summary>
    public bool IsDigestName => Size > 4;

    /// <summary>
    /// Gets the Name data as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            if(Storage is null)
            {
                return [];
            }

            return Storage.Memory.Span.Slice(0, Size);
        }
    }

    /// <summary>
    /// Gets the Name data as read-only memory that aliases this instance's pooled storage — for a borrowing
    /// consumer such as a cpHash handle-name area concatenation, valid until <see cref="Dispose"/> and never
    /// copied into an untracked array.
    /// </summary>
    /// <returns>The Name bytes.</returns>
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
    public int SerializedSize => sizeof(ushort) + Size;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)Size);

        if(Size > 0)
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
    public static Tpm2bName Parse(ref TpmReader reader, BaseMemoryPool pool)
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
    public static Tpm2bName Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
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
    /// Adopts an already-filled pooled buffer as this structure's storage: ownership of
    /// <paramref name="storage"/> transfers to the returned instance, with no second rental and no copy — the
    /// zero-copy counterpart of <see cref="Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> for a producer that
    /// rented the octets and wrote them itself.
    /// </summary>
    /// <remarks>
    /// A <paramref name="size"/> of zero yields the shared <see cref="Empty"/> singleton and releases
    /// <paramref name="storage"/> here, since the singleton rents nothing and its <see cref="Dispose"/> is a
    /// no-op. An argument that does not describe a valid <c>TPM2B_NAME</c> likewise releases
    /// <paramref name="storage"/> before the exception leaves, so a rejected adoption never orphans the
    /// rental. The bound checked here is the <c>TPM2B</c> size field's own 16-bit width, since the octets come
    /// from the producing side rather than from a caller: the table's content bound is enforced where octets
    /// arrive from the wire (<see cref="Parse"/>) or are copied in from an untrusted span
    /// (<see cref="Create(ReadOnlySpan{byte}, BaseMemoryPool)"/>).
    /// </remarks>
    /// <param name="storage">The pooled buffer whose leading octets hold the value; ownership transfers to the returned instance or is released here.</param>
    /// <param name="size">The number of valid octets at the head of <paramref name="storage"/>.</param>
    /// <returns>The adopted value.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="storage"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="size"/> is negative, exceeds <paramref name="storage"/>'s length, or exceeds the 16-bit width of a <c>TPM2B</c> size field.</exception>
    public static Tpm2bName FromMarshaled(IMemoryOwner<byte> storage, int size)
    {
        ArgumentNullException.ThrowIfNull(storage);

        try
        {
            ArgumentOutOfRangeException.ThrowIfNegative(size);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(size, storage.Memory.Length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(size, ushort.MaxValue);
        }
        catch
        {
            storage.Dispose();
            throw;
        }

        if(size == 0)
        {
            storage.Dispose();

            return Empty;
        }

        return new Tpm2bName(storage, size);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            Storage?.Dispose();
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