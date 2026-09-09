using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer carrying the event data of <c>TPM2_PCR_Event()</c> (TPM2B_EVENT).
/// </summary>
/// <remarks>
/// <para>
/// The event recorded into a PCR in one command: the TPM hashes these octets under every implemented hash
/// algorithm and extends the named register with each bank's digest (TPM 2.0 Library Part 3, clause 22.3.1).
/// The content is public — it is the log entry itself — so this carrier holds no
/// <see cref="Verifiable.Cryptography.SensitiveMemory"/> tag, matching <see cref="Tpm2bMaxBuffer"/>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the buffer, at most MaxSize.
///     BYTE buffer[size];                       // The event data.
/// } TPM2B_EVENT;
/// </code>
/// <para>
/// Table 95 bounds the payload at 1,024 octets (<c>buffer[size] {:1024}</c>), which Part 3, clause 22.3.1
/// restates as the range every TPM shall support: "A TPM shall support an eventData.size of zero through 1,024
/// inclusive". <see cref="MaxSize"/> is that bound.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.3.7, Table 95.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bEvent: IDisposable
{
    /// <summary>
    /// The bound on the event payload, in octets: Table 95's <c>{:1024}</c>.
    /// </summary>
    public const int MaxSize = 1024;

    /// <summary>
    /// The shared zero-length instance backing every empty event.
    /// </summary>
    private static Tpm2bEvent EmptyInstance { get; } = new();

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
    private Tpm2bEvent()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes an event over pooled storage.
    /// </summary>
    /// <param name="storage">The pooled storage this instance takes ownership of.</param>
    /// <param name="length">The number of valid octets at the start of <paramref name="storage"/>.</param>
    private Tpm2bEvent(IMemoryOwner<byte> storage, int length)
    {
        Storage = storage;
        Length = length;
    }

    /// <summary>
    /// Gets the shared zero-length event — "An eventData.size of zero indicates that there is no data, but the
    /// indicated operations will still occur" (Part 3, clause 22.3.1). It rents nothing and its
    /// <see cref="Dispose"/> is a no-op.
    /// </summary>
    public static Tpm2bEvent Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this event carries no octets.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the event data in octets.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the event data as a read-only span.
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
    /// Gets the event data as read-only memory that aliases this instance's pooled storage — for a borrowing
    /// consumer, valid until <see cref="Dispose"/> and never copied into an untracked array.
    /// </summary>
    /// <returns>The event octets.</returns>
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
    /// Parses an event from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed event.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">The wire size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>).</exception>
    public static Tpm2bEvent Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Event size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(storage.Memory.Span[..size]);

            return new Tpm2bEvent(storage, size);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates an event from the specified octets.
    /// </summary>
    /// <param name="bytes">The event octets.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created event; the caller owns it. An empty input yields <see cref="Empty"/>, which rents nothing.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bEvent Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Event too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        try
        {
            bytes.CopyTo(storage.Memory.Span);

            return new Tpm2bEvent(storage, bytes.Length);
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
    private string DebuggerDisplay => $"TPM2B_EVENT({Length} bytes)";
}
