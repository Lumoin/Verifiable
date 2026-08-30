using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer holding a credential identity object (TPM2B_ID_OBJECT).
/// </summary>
/// <remarks>
/// <para>
/// The opaque, integrity-protected and encrypted credential blob produced by <c>TPM2_MakeCredential</c> and
/// consumed by <c>TPM2_ActivateCredential</c>. It wraps a TPMS_ID_OBJECT (an integrity HMAC over an encrypted
/// identity) and is treated here as opaque bytes — it is produced by one TPM operation and handed back to
/// another, never inspected by the host.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the credential blob.
///     BYTE   credential[size];                 // A marshaled TPMS_ID_OBJECT.
/// } TPM2B_ID_OBJECT;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.4.3, Table 245.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bIdObject: IDisposable
{
    /// <summary>
    /// Maximum size of the credential blob: a TPMS_ID_OBJECT is two TPM2B_DIGEST values (an integrity HMAC and
    /// an encrypted identity), each at most a SHA-512 digest.
    /// </summary>
    public const int MaxSize = 2 * (sizeof(ushort) + 64);

    private static Tpm2bIdObject EmptyInstance { get; } = new();

    private IMemoryOwner<byte>? Storage { get; }
    private bool disposed;

    /// <summary>
    /// Initializes an empty credential blob.
    /// </summary>
    private Tpm2bIdObject()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a new credential blob with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the blob bytes.</param>
    /// <param name="length">The actual length of the blob.</param>
    private Tpm2bIdObject(IMemoryOwner<byte> storage, int length)
    {
        this.Storage = storage;
        this.Length = length;
    }

    /// <summary>
    /// Gets an empty credential blob.
    /// </summary>
    public static Tpm2bIdObject Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this blob is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the blob.
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
    /// Gets the serialized size of this structure.
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
    /// Parses a credential blob from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The declared size is checked against <see cref="MaxSize"/> and then <see cref="TpmReader.Remaining"/>
    /// before any pooled buffer is rented, so a truncated or oversized frame throws without ever orphaning a
    /// rental — the same ordering <see cref="Tpm2bDigest.Parse(ref TpmReader, BaseMemoryPool)"/> and
    /// <see cref="Tpm2bPrivate.Parse(ref TpmReader, BaseMemoryPool)"/> use.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed credential blob.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>, or exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static Tpm2bIdObject Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Credential blob size {size} exceeds maximum {MaxSize}.");
        }

        if(size > reader.Remaining)
        {
            throw new InvalidOperationException($"Credential blob size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bIdObject(storage, size);
    }

    /// <summary>
    /// Creates a credential blob from the specified bytes.
    /// </summary>
    /// <param name="bytes">The blob bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created credential blob.</returns>
    public static Tpm2bIdObject Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Credential blob too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bIdObject(storage, bytes.Length);
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
    /// no-op. An argument that does not describe a valid <c>TPM2B_ID_OBJECT</c> likewise releases
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
    public static Tpm2bIdObject FromMarshaled(IMemoryOwner<byte> storage, int length)
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

        return new Tpm2bIdObject(storage, length);
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

    private string DebuggerDisplay => $"TPM2B_ID_OBJECT({Length} bytes)";
}
