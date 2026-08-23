using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer for the commands that move a large block of data (TPM2B_MAX_BUFFER).
/// </summary>
/// <remarks>
/// <para>
/// Carries the bulk payload of the commands Part 2 names for it — <c>TPM2_Hash()</c>,
/// <c>TPM2_SequenceUpdate()</c>, <c>TPM2_FieldUpgradeData()</c> — and of <c>TPM2_AC_Send()</c>'s
/// <c>acDataIn</c>. It is NOT the NV data type: the NV commands' <c>data</c> parameter is a
/// <c>TPM2B_MAX_NV_BUFFER</c> bounded by <c>MAX_NV_BUFFER_SIZE</c> (Part 2, clause 10.4.9, Table 99), which
/// <see cref="Tpm2bMaxNvBuffer"/> carries. The content is public — it is caller-supplied input to a hashing or
/// transport command — so this carrier holds no <see cref="Verifiable.Cryptography.SensitiveMemory"/> tag,
/// matching <see cref="Tpm2bName"/> and <see cref="Tpm2bData"/> rather than the secret-shaped
/// <see cref="Tpm2bDigest"/>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the buffer, at most MaxSize.
///     BYTE buffer[size];                       // The data.
/// } TPM2B_MAX_BUFFER;
/// </code>
/// <para>
/// Table 98 bounds the payload by <c>MAX_2B_BUFFER_SIZE</c> (<c>buffer[size] {:MAX_2B_BUFFER_SIZE}</c>), and
/// clause 10.4.8's own prose above that table states only the constant's floor: "MAX_2B_BUFFER_SIZE is
/// TPM-dependent but is required to be at least 1,024." A real TPM reports its own bound through
/// <c>TPM_PT_INPUT_BUFFER</c>. <see cref="MaxSize"/> (1024 octets) is this library's own
/// <c>MAX_2B_BUFFER_SIZE</c>, that stated floor.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.4.8, Table 98, printed page 135.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bMaxBuffer: IDisposable
{
    /// <summary>
    /// This library's implementation bound for the buffer payload, in octets: Table 98's
    /// <c>{:MAX_2B_BUFFER_SIZE}</c>, a constant clause 10.4.8's prose (printed page 135) declares
    /// TPM-dependent and required to be at least 1,024.
    /// </summary>
    public const int MaxSize = 1024;

    /// <summary>
    /// The shared zero-length instance backing every empty buffer.
    /// </summary>
    private static Tpm2bMaxBuffer EmptyInstance { get; } = new();

    /// <summary>
    /// The pooled storage, or <see langword="null"/> for <see cref="Empty"/>.
    /// </summary>
    private IMemoryOwner<byte>? Storage { get; }

    /// <summary>
    /// Whether <see cref="Dispose"/> has already released <see cref="Storage"/>.
    /// </summary>
    private bool disposed;

    /// <summary>
    /// Initializes the zero-length instance, which rents nothing and is immune to disposal.
    /// </summary>
    private Tpm2bMaxBuffer()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a buffer over pooled storage.
    /// </summary>
    /// <param name="storage">The pooled storage this instance takes ownership of.</param>
    /// <param name="length">The number of valid octets at the start of <paramref name="storage"/>.</param>
    private Tpm2bMaxBuffer(IMemoryOwner<byte> storage, int length)
    {
        Storage = storage;
        Length = length;
    }

    /// <summary>
    /// Gets the shared zero-length buffer. It rents nothing and its <see cref="Dispose"/> is a no-op.
    /// </summary>
    public static Tpm2bMaxBuffer Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this buffer carries no octets.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the buffer in octets.
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

            return Storage.Memory.Span[..Length];
        }
    }

    /// <summary>
    /// Gets the buffer data as read-only memory that aliases this instance's pooled storage — for a borrowing
    /// consumer, valid until <see cref="Dispose"/> and never copied into an untracked array.
    /// </summary>
    /// <returns>The buffer octets.</returns>
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
    /// Gets the serialized size of this structure: the <c>UINT16</c> size prefix and the octets themselves.
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
    /// Parses a buffer from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed buffer.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">The wire size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>).</exception>
    public static Tpm2bMaxBuffer Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Buffer size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(storage.Memory.Span[..size]);

            return new Tpm2bMaxBuffer(storage, size);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates a buffer from the specified octets.
    /// </summary>
    /// <param name="bytes">The buffer octets.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created buffer; the caller owns it. An empty input yields <see cref="Empty"/>, which rents nothing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bMaxBuffer Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Buffer too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        try
        {
            bytes.CopyTo(storage.Memory.Span);

            return new Tpm2bMaxBuffer(storage, bytes.Length);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases the pooled storage. Repeated calls and calls on <see cref="Empty"/> do nothing.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            Storage?.Dispose();
            disposed = true;
        }
    }

    /// <summary>
    /// The debugger's one-line rendering: the octet count only, never the octets themselves.
    /// </summary>
    private string DebuggerDisplay => $"TPM2B_MAX_BUFFER({Length} bytes)";
}
