using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer carrying an authorization timeout value (TPM2B_TIMEOUT).
/// </summary>
/// <remarks>
/// <para>
/// Returned by commands such as <c>TPM2_PolicySecret()</c> and <c>TPM2_PolicySigned()</c> to report how long
/// their authorization remains valid.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the timeout value; at most sizeof(UINT64) (8).
///     BYTE buffer[size];                       // The timeout value, big-endian.
/// } TPM2B_TIMEOUT;
/// </code>
/// <para>
/// Part 2, Table 100's Reference Code note: "the MSb is used as a flag to indicate whether a ticket expires
/// on TPM Reset or TPM Restart" — the most-significant bit of the full 8-octet form, exposed here as
/// <see cref="ExpiresOnReset"/>, alongside the bits it shares with <see cref="Value"/> itself.
/// </para>
/// <para>
/// The content is not secret key material, so this carrier holds no
/// <see cref="Verifiable.Cryptography.SensitiveMemory"/> tag; it follows the hand-rolled pooled shape of
/// <see cref="Tpm2bName"/> and <see cref="Tpm2bData"/>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.4.10, Table 100.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bTimeout: IDisposable
{
    /// <summary>
    /// Maximum size of the timeout value in octets (<c>sizeof(UINT64)</c>, Part 2, Table 100).
    /// </summary>
    public const int MaxSize = sizeof(ulong);

    /// <summary>
    /// The most-significant bit of the full 8-octet form, repurposed by the Reference Code as the
    /// expires-on-reset flag (Part 2, Table 100 note).
    /// </summary>
    private const ulong ExpiresOnResetFlag = 0x8000_0000_0000_0000UL;

    private static Tpm2bTimeout EmptyInstance { get; } = new();

    private IMemoryOwner<byte>? Storage { get; }
    private bool disposed;

    /// <summary>
    /// Initializes an empty timeout.
    /// </summary>
    private Tpm2bTimeout()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a new timeout with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the timeout bytes.</param>
    /// <param name="length">The actual length of the timeout value.</param>
    private Tpm2bTimeout(IMemoryOwner<byte> storage, int length)
    {
        this.Storage = storage;
        this.Length = length;
    }

    /// <summary>
    /// Gets an empty timeout.
    /// </summary>
    public static Tpm2bTimeout Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this timeout is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the timeout value in bytes.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the timeout data as a read-only span.
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
    /// Gets the timeout data as read-only memory that aliases this instance's pooled storage — for a
    /// borrowing consumer, valid until <see cref="Dispose"/> and never copied into an untracked array.
    /// </summary>
    /// <returns>The timeout bytes.</returns>
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
    /// Gets the wire octets read as a big-endian unsigned 64-bit integer, zero-extended on the left when
    /// <see cref="Length"/> is less than <see cref="MaxSize"/>. This is the raw 8-octet form, including
    /// whatever bit 63 carries — see <see cref="ExpiresOnReset"/> to read that bit alone.
    /// </summary>
    public ulong Value
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            Span<byte> widened = stackalloc byte[MaxSize];
            widened.Clear();
            Span.CopyTo(widened[(MaxSize - Length)..]);

            return BinaryPrimitives.ReadUInt64BigEndian(widened);
        }
    }

    /// <summary>
    /// Gets whether bit 63 of the 8-octet form is set — the Reference Code's flag for whether the ticket this
    /// timeout accompanies expires on TPM Reset or TPM Restart (Part 2, Table 100 note).
    /// </summary>
    public bool ExpiresOnReset => (Value & ExpiresOnResetFlag) != 0;

    /// <summary>
    /// Gets the deadline magnitude alone: <see cref="Value"/> with bit 63 masked off. This is the form the
    /// session's own timeout tracking compares, since Part 3, Section 23.2.4's "the lesser of the two" rule
    /// ranks deadlines, not the expires-on-reset flag that shares the field.
    /// </summary>
    public ulong Magnitude => Value & ~ExpiresOnResetFlag;

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
    /// Parses a timeout from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed timeout.</returns>
    /// <exception cref="InvalidOperationException">The wire size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>).</exception>
    public static Tpm2bTimeout Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Timeout size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bTimeout(storage, size);
    }

    /// <summary>
    /// Creates a timeout from the specified bytes.
    /// </summary>
    /// <param name="bytes">The timeout bytes, big-endian.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created timeout.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bTimeout Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Timeout too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bTimeout(storage, bytes.Length);
    }

    /// <summary>
    /// Creates a timeout from a 64-bit value and the Reference Code's expires-on-reset flag, packing both
    /// into the full 8-octet wire form. Bit 63 is that flag (Part 2, Table 100's Reference Code note), so
    /// <paramref name="expiresOnReset"/> sets it and every octet of <paramref name="value"/> otherwise reaches
    /// the wire as supplied — a caller that already carries the flag inside <paramref name="value"/> keeps it.
    /// </summary>
    /// <param name="value">The timeout magnitude, optionally already carrying the flag in its bit 63.</param>
    /// <param name="expiresOnReset">Whether the accompanying ticket expires on TPM Reset or TPM Restart.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created timeout.</returns>
    public static Tpm2bTimeout Create(ulong value, bool expiresOnReset, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ulong combined = value | (expiresOnReset ? ExpiresOnResetFlag : 0UL);

        IMemoryOwner<byte> storage = pool.Rent(MaxSize);
        BinaryPrimitives.WriteUInt64BigEndian(storage.Memory.Span.Slice(0, MaxSize), combined);

        return new Tpm2bTimeout(storage, MaxSize);
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

    private string DebuggerDisplay => $"TPM2B_TIMEOUT({Length} bytes)";
}
