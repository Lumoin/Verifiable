using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer for NV data commands (TPM2B_MAX_NV_BUFFER).
/// </summary>
/// <remarks>
/// <para>
/// Carries the payload of <c>TPM2_NV_Read()</c>, <c>TPM2_NV_Write()</c>, and <c>TPM2_NV_Certify()</c>. The
/// content is public — it is the caller-visible bytes of an NV Index — so this carrier holds no
/// <see cref="Verifiable.Cryptography.SensitiveMemory"/> tag, matching <see cref="Tpm2bName"/> and
/// <see cref="Tpm2bData"/> rather than the secret-shaped <see cref="Tpm2bDigest"/>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the buffer, at most MaxSize.
///     BYTE buffer[size];                       // The NV data.
/// } TPM2B_MAX_NV_BUFFER;
/// </code>
/// <para>
/// Part 2, Table 99 declares <c>MAX_NV_BUFFER_SIZE</c> TPM-dependent, leaving no normative fixed value; a real
/// TPM reports its own bound through <c>TPM_PT_NV_BUFFER_MAX</c>. <see cref="MaxSize"/> (2048 octets) is this
/// library's own <c>MAX_NV_BUFFER_SIZE</c> — the bound the NV data-parameter sites (<c>TPM2_NV_Read()</c>,
/// <c>TPM2_NV_Write()</c>, and the <c>TPM2_NV_Certify()</c> size parameter) enforce when parsing or
/// constructing an NV payload.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.4.9, Table 99.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bMaxNvBuffer: IDisposable
{
    /// <summary>
    /// This library's implementation bound for the NV buffer payload, in octets (Part 2, Table 99:
    /// <c>MAX_NV_BUFFER_SIZE</c> is TPM-dependent; no value is normative).
    /// </summary>
    public const int MaxSize = 2048;

    private static Tpm2bMaxNvBuffer EmptyInstance { get; } = new();

    private IMemoryOwner<byte>? Storage { get; }
    private bool disposed;

    /// <summary>
    /// Initializes an empty NV buffer.
    /// </summary>
    private Tpm2bMaxNvBuffer()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a new NV buffer with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the buffer bytes.</param>
    /// <param name="length">The actual length of the buffer.</param>
    private Tpm2bMaxNvBuffer(IMemoryOwner<byte> storage, int length)
    {
        this.Storage = storage;
        this.Length = length;
    }

    /// <summary>
    /// Gets an empty NV buffer.
    /// </summary>
    public static Tpm2bMaxNvBuffer Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this buffer is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the buffer in bytes.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the buffer data as a read-only span.
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
    /// Gets the buffer data as read-only memory that aliases this instance's pooled storage — for a
    /// borrowing consumer, valid until <see cref="Dispose"/> and never copied into an untracked array.
    /// </summary>
    /// <returns>The buffer bytes.</returns>
    public ReadOnlyMemory<byte> AsReadOnlyMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if(Storage is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return Storage.Memory.Slice(0, Length);
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
    /// Parses an NV buffer from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed NV buffer.</returns>
    /// <exception cref="InvalidOperationException">The wire size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>).</exception>
    public static Tpm2bMaxNvBuffer Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"NV buffer size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(storage.Memory.Span.Slice(0, size));

            return new Tpm2bMaxNvBuffer(storage, size);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates an NV buffer from the specified bytes.
    /// </summary>
    /// <param name="bytes">The buffer bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created NV buffer.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bMaxNvBuffer Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"NV buffer too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        try
        {
            bytes.CopyTo(storage.Memory.Span);

            return new Tpm2bMaxNvBuffer(storage, bytes.Length);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Takes ownership of storage a caller has already rented and filled — the shape a composing verb uses,
    /// where the payload is laid straight into the rental by a writer rather than copied in afterwards.
    /// </summary>
    /// <param name="storage">The pooled storage to take ownership of.</param>
    /// <param name="length">The number of valid octets at the start of <paramref name="storage"/>.</param>
    /// <returns>The NV buffer; the caller no longer owns <paramref name="storage"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="storage"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="length"/> is negative, exceeds the storage, or exceeds <see cref="MaxSize"/>.</exception>
    public static Tpm2bMaxNvBuffer Adopt(IMemoryOwner<byte> storage, int length)
    {
        ArgumentNullException.ThrowIfNull(storage);
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, storage.Memory.Length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, MaxSize);

        return new Tpm2bMaxNvBuffer(storage, length);
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

    private string DebuggerDisplay => $"TPM2B_MAX_NV_BUFFER({Length} bytes)";
}
