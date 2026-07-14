using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

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
/// Specification reference: TPM 2.0 Library Part 2, Section 12.4.2, Table 207.
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
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed credential blob.</returns>
    public static Tpm2bIdObject Parse(ref TpmReader reader, MemoryPool<byte> pool)
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
    public static Tpm2bIdObject Create(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
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