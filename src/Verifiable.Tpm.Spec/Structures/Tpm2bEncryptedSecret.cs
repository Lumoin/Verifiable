using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer holding an encrypted secret seed (TPM2B_ENCRYPTED_SECRET).
/// </summary>
/// <remarks>
/// <para>
/// The asymmetrically-protected seed produced by <c>TPM2_MakeCredential</c> (and used in duplication and import).
/// In credential activation it carries the seed encrypted to the credential key's public area; the host treats
/// it as opaque bytes, passing it from <c>TPM2_MakeCredential</c> straight to <c>TPM2_ActivateCredential</c>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the encrypted secret.
///     BYTE   secret[size];                     // A marshaled TPMU_ENCRYPTED_SECRET.
/// } TPM2B_ENCRYPTED_SECRET;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.4.3, Table 210, page 180.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bEncryptedSecret: IDisposable
{
    /// <summary>
    /// Maximum size of the encrypted secret: <c>sizeof(TPMU_ENCRYPTED_SECRET)</c>, bounded by the largest
    /// supported asymmetric key (an RSA-4096 modulus).
    /// </summary>
    public const int MaxSize = 512;

    private static Tpm2bEncryptedSecret EmptyInstance { get; } = new();

    private IMemoryOwner<byte>? Storage { get; }
    private bool disposed;

    /// <summary>
    /// Initializes an empty encrypted secret.
    /// </summary>
    private Tpm2bEncryptedSecret()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a new encrypted secret with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the secret bytes.</param>
    /// <param name="length">The actual length of the secret.</param>
    private Tpm2bEncryptedSecret(IMemoryOwner<byte> storage, int length)
    {
        this.Storage = storage;
        this.Length = length;
    }

    /// <summary>
    /// Gets an empty encrypted secret.
    /// </summary>
    public static Tpm2bEncryptedSecret Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this secret is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the secret.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the secret as a read-only span.
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
    /// Gets the secret as read-only memory, for a consumer that must hold the octets across an
    /// <see langword="await"/> — an asymmetric recovery primitive — where a span cannot travel.
    /// </summary>
    /// <remarks>
    /// The memory aliases this instance's own pooled storage and is valid only while this instance is alive;
    /// reading it after <see cref="Dispose"/> observes memory the pool has taken back.
    /// </remarks>
    public ReadOnlyMemory<byte> AsReadOnlyMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(Storage is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return Storage.Memory[..Length];
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
    /// Parses an encrypted secret from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed encrypted secret.</returns>
    public static Tpm2bEncryptedSecret Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Encrypted secret size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bEncryptedSecret(storage, size);
    }

    /// <summary>
    /// Creates an encrypted secret from the specified bytes.
    /// </summary>
    /// <param name="bytes">The secret bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created encrypted secret.</returns>
    public static Tpm2bEncryptedSecret Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Encrypted secret too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bEncryptedSecret(storage, bytes.Length);
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
    /// no-op. An argument that does not describe a valid <c>TPM2B_ENCRYPTED_SECRET</c> likewise releases
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
    public static Tpm2bEncryptedSecret FromMarshaled(IMemoryOwner<byte> storage, int length)
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

        return new Tpm2bEncryptedSecret(storage, length);
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

    private string DebuggerDisplay => $"TPM2B_ENCRYPTED_SECRET({Length} bytes)";
}