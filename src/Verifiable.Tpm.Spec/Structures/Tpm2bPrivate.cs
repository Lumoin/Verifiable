using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer holding the encrypted private area of an object (TPM2B_PRIVATE).
/// </summary>
/// <remarks>
/// <para>
/// The buffer is an opaque blob produced by <c>TPM2_Create()</c> (and the other object-creating
/// commands): the object's sensitive area wrapped under its parent's symmetric key and integrity
/// protected by the TPM. It is meaningful only to the TPM that produced it. The caller stores it (for
/// example on disk) and presents it again to <c>TPM2_Load()</c> to bring the object back into a
/// transient slot; the plaintext key never leaves the TPM.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the wrapped sensitive area, 0 for an empty blob.
///     BYTE   buffer[size];                     // The encrypted, integrity-protected sensitive area.
/// } TPM2B_PRIVATE;
/// </code>
/// <para>
/// Unlike <see cref="Tpm2bData"/> there is no small fixed maximum: the wrapped sensitive area of an RSA
/// or ECC key is hundreds of octets, so the size is bounded only by the UINT16 prefix and the octets the
/// TPM returns.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.3.7 (Table 227).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bPrivate: IDisposable, ITpmWireType
{
    private static Tpm2bPrivate EmptyInstance { get; } = new();

    private IMemoryOwner<byte>? Storage { get; }
    private bool disposed;

    /// <summary>
    /// Initializes an empty private blob.
    /// </summary>
    private Tpm2bPrivate()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a new private blob with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the blob octets.</param>
    /// <param name="length">The actual length of the blob.</param>
    private Tpm2bPrivate(IMemoryOwner<byte> storage, int length)
    {
        this.Storage = storage;
        this.Length = length;
    }

    /// <summary>
    /// Gets an empty private blob.
    /// </summary>
    public static Tpm2bPrivate Empty => EmptyInstance;

    /// <summary>
    /// Gets a value indicating whether this blob is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the blob in octets.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the blob as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(Storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return Storage.Memory.Span.Slice(0, Length);
        }
    }

    /// <summary>
    /// Gets the serialized size (2-byte size prefix + blob).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Length;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)Length);

        if(Length > 0)
        {
            writer.WriteBytes(Span);
        }
    }

    /// <summary>
    /// Parses a private blob from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the blob.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed private blob.</returns>
    public static Tpm2bPrivate Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        //The blob content is opaque: an encrypted, TPM-internal structure this code never interprets, and
        //whose integrity the TPM itself verifies on TPM2_Load. What this code must still validate is the
        //framing — the declared size cannot exceed the octets present. A blob is typically reloaded from
        //caller storage (disk) before going back to the TPM, so a truncated or corrupt size prefix is a
        //realistic input; reject it here rather than over-reading the buffer. There is deliberately no small
        //fixed maximum (a wrapped key is hundreds of octets).
        if(size > reader.Remaining)
        {
            throw new InvalidOperationException(
                $"TPM2B_PRIVATE size {size} exceeds the {reader.Remaining} octets available; the blob is truncated or corrupt.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bPrivate(storage, size);
    }

    /// <summary>
    /// Creates a private blob from the specified octets, copying them into pooled storage.
    /// </summary>
    /// <remarks>
    /// An empty span yields the shared <see cref="Empty"/> singleton, whose <see cref="Dispose"/> is a
    /// no-op; a consumer that "owns" such a blob therefore disposes nothing.
    /// </remarks>
    /// <param name="bytes">The blob octets (for example the <c>outPrivate</c> of a prior <c>TPM2_Create()</c>).</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created private blob.</returns>
    public static Tpm2bPrivate Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bPrivate(storage, bytes.Length);
    }

    /// <summary>
    /// Adopts an already-filled pooled buffer as this structure's storage: ownership of
    /// <paramref name="storage"/> transfers to the returned instance, with no second rental and no copy — the
    /// zero-copy counterpart of <see cref="Create(ReadOnlySpan{byte}, BaseMemoryPool)"/> for a producer that
    /// rented the octets and wrote them itself.
    /// </summary>
    /// <remarks>
    /// A <paramref name="length"/> of zero yields the shared <see cref="Empty"/> singleton and releases
    /// <paramref name="storage"/> here, since the singleton rents nothing and its <see cref="Dispose"/> is a
    /// no-op. An argument that does not describe a valid <c>TPM2B_PRIVATE</c> likewise releases
    /// <paramref name="storage"/> before the exception leaves, so a rejected adoption never orphans the
    /// rental. The bound checked here is the <c>TPM2B</c> size field's own 16-bit width, since the octets come
    /// from the producing side rather than from a caller: the table's content bound is enforced where octets
    /// arrive from the wire (<see cref="Parse"/>) or are copied in from an untrusted span
    /// (<see cref="Create(ReadOnlySpan{byte}, BaseMemoryPool)"/>).
    /// </remarks>
    /// <param name="storage">The pooled buffer whose leading octets hold the value; ownership transfers to the returned instance or is released here.</param>
    /// <param name="length">The number of valid octets at the head of <paramref name="storage"/>.</param>
    /// <returns>The adopted value.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="storage"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is negative, exceeds <paramref name="storage"/>'s length, or exceeds the 16-bit width of a <c>TPM2B</c> size field.</exception>
    public static Tpm2bPrivate FromMarshaled(IMemoryOwner<byte> storage, int length)
    {
        ArgumentNullException.ThrowIfNull(storage);

        try
        {
            ArgumentOutOfRangeException.ThrowIfNegative(length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, storage.Memory.Length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, ushort.MaxValue);
        }
        catch
        {
            storage.Dispose();
            throw;
        }

        if(length == 0)
        {
            storage.Dispose();

            return Empty;
        }

        return new Tpm2bPrivate(storage, length);
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

    private string DebuggerDisplay => $"TPM2B_PRIVATE({Length} bytes)";
}