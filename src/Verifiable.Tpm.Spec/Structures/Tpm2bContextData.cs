using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer carrying a saved context's opaque octets (TPM2B_CONTEXT_DATA).
/// </summary>
/// <remarks>
/// <para>
/// "This structure is used in a TPMS_CONTEXT." (TPM 2.0 Library Part 2, clause 14.4). The octets it carries
/// have no wire-normative internal layout: "The internal structure TPMS_CONTEXT_DATA of the actual context is
/// vendor specific." (TPM 2.0 Library Part 1, clause 27.2.1). The informative Tables 257 and 258 name the SHAPE
/// this TPM's own octets follow — a leading <c>TPM2B_DIGEST</c> integrity value followed by the encrypted
/// sensitive area (<c>TPM2B_CONTEXT_SENSITIVE</c>) — without making either table itself part of the wire; only
/// this buffer's own <c>UINT16</c> size prefix and octets are exchanged.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the buffer, at most sizeof(TPMS_CONTEXT_DATA).
///     BYTE buffer[size];                       // The opaque context octets.
/// } TPM2B_CONTEXT_DATA;
/// </code>
/// <para>
/// Table 259 bounds the payload by <c>{:sizeof(TPMS_CONTEXT_DATA)}</c> — the size of the vendor-specific
/// structure this exact TPM produces, not a wire-shared constant. <see cref="MaxSize"/> (the <c>UINT16</c>
/// ceiling, 65535 octets) is this library's own bound: the largest vendor blob this simulator produces is
/// itself bounded only by the resource being saved (for example a sequence object's retained segments), so the
/// buffer's own size field width is the only ceiling this type enforces at parse time.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 14.4, Table 259.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bContextData: IDisposable
{
    /// <summary>
    /// This library's implementation bound for the buffer payload, in octets: 65535, the <c>UINT16</c> size
    /// field's own width and the largest value that field can carry. Table 259's
    /// <c>{:sizeof(TPMS_CONTEXT_DATA)}</c> bound is a vendor-specific quantity this simulator does not fix
    /// independently of that width.
    /// </summary>
    public const int MaxSize = 65535;

    /// <summary>
    /// The shared zero-length instance backing every empty buffer.
    /// </summary>
    private static Tpm2bContextData EmptyInstance { get; } = new();

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
    private Tpm2bContextData()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a buffer over pooled storage.
    /// </summary>
    /// <param name="storage">The pooled storage this instance takes ownership of.</param>
    /// <param name="length">The number of valid octets at the start of <paramref name="storage"/>.</param>
    private Tpm2bContextData(IMemoryOwner<byte> storage, int length)
    {
        Storage = storage;
        Length = length;
    }

    /// <summary>
    /// Gets the shared zero-length buffer. It rents nothing and its <see cref="Dispose"/> is a no-op.
    /// </summary>
    public static Tpm2bContextData Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this buffer carries no octets.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the buffer in octets.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the length of the buffer in octets. An alias of <see cref="Length"/> matching the wire field's own
    /// name (<c>size</c>).
    /// </summary>
    public int Size => Length;

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
    /// <remarks>
    /// <paramref name="reader"/>'s <c>size</c> field is itself a <c>UINT16</c>, so a value it yields can never
    /// exceed <see cref="MaxSize"/> (65535, that same field's own ceiling): the size-exceeds-<see cref="MaxSize"/>
    /// guard below is a structural assertion the wire cannot trigger, not a condition this parse path reaches.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed buffer.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="InvalidOperationException">The wire size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>) — unreachable from a wire frame, since <see cref="MaxSize"/> is the <c>UINT16</c> size field's own ceiling.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/> (<c>TPM_RC_INSUFFICIENT</c>).</exception>
    public static Tpm2bContextData Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Context data size {size} exceeds maximum {MaxSize}.");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), size, $"Context data size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(storage.Memory.Span[..size]);

            return new Tpm2bContextData(storage, size);
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
    public static Tpm2bContextData Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
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

            return new Tpm2bContextData(storage, bytes.Length);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Adopts an already-filled pooled buffer as this structure's storage: ownership of <paramref
    /// name="storage"/> transfers to the returned instance, with no second rental and no copy — the effect that
    /// marshals a <see cref="TpmsContext"/>'s fields into a rented buffer adopts that same buffer here rather
    /// than renting and copying a second time.
    /// </summary>
    /// <remarks>
    /// A <paramref name="size"/> of zero yields the shared <see cref="Empty"/> singleton and releases <paramref
    /// name="storage"/> here, since the singleton rents nothing and its <see cref="Dispose"/> is a no-op. An
    /// argument that does not describe a valid <c>TPM2B_CONTEXT_DATA</c> likewise releases <paramref
    /// name="storage"/> before the exception leaves, so a rejected adoption never orphans the rental.
    /// </remarks>
    /// <param name="storage">The pooled buffer whose leading octets hold the value; ownership transfers to the returned instance or is released here.</param>
    /// <param name="size">The number of valid octets at the head of <paramref name="storage"/>.</param>
    /// <returns>The adopted value.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="storage"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="size"/> is negative, exceeds <paramref name="storage"/>'s length, or exceeds <see cref="MaxSize"/>.</exception>
    public static Tpm2bContextData FromMarshaled(IMemoryOwner<byte> storage, int size)
    {
        ArgumentNullException.ThrowIfNull(storage);

        try
        {
            ArgumentOutOfRangeException.ThrowIfNegative(size);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(size, storage.Memory.Length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(size, MaxSize);
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

        return new Tpm2bContextData(storage, size);
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
    private string DebuggerDisplay => $"TPM2B_CONTEXT_DATA({Length} bytes)";
}
