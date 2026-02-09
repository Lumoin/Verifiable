using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// General purpose data buffer (TPM2B_DATA).
/// </summary>
/// <remarks>
/// <para>
/// Used for miscellaneous data in various commands. In <c>TPM2_CreatePrimary()</c>,
/// this is the <c>outsideInfo</c> parameter which is included in the creation data
/// but otherwise not used by the TPM.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of buffer (0 to sizeof(TPMT_HA)).
///     BYTE buffer[size];                       // The data.
/// } TPM2B_DATA;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.4.3.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bData: IDisposable
{
    /// <summary>
    /// Maximum size of the data buffer.
    /// </summary>
    public const int MaxSize = 64; // sizeof(TPMT_HA) - largest hash.

    private static readonly Tpm2bData EmptyInstance = new();

    private readonly IMemoryOwner<byte>? storage;
    private readonly int length;
    private bool disposed;

    /// <summary>
    /// Initializes an empty data buffer.
    /// </summary>
    private Tpm2bData()
    {
        storage = null;
        length = 0;
    }

    /// <summary>
    /// Initializes a new data buffer with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the data bytes.</param>
    /// <param name="length">The actual length of the data.</param>
    private Tpm2bData(IMemoryOwner<byte> storage, int length)
    {
        this.storage = storage;
        this.length = length;
    }

    /// <summary>
    /// Gets an empty data buffer.
    /// </summary>
    public static Tpm2bData Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this buffer is empty.
    /// </summary>
    public bool IsEmpty => length == 0;

    /// <summary>
    /// Gets the length of the data.
    /// </summary>
    public int Length => length;

    /// <summary>
    /// Gets the data as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            if(storage is null)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return storage.Memory.Span.Slice(0, length);
        }
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + length;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)length);

        if(length > 0)
        {
            writer.WriteBytes(Span);
        }
    }

    /// <summary>
    /// Parses a data buffer from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed data buffer.</returns>
    public static Tpm2bData Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Data size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bData(storage, size);
    }

    /// <summary>
    /// Creates a data buffer from the specified bytes.
    /// </summary>
    /// <param name="bytes">The data bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created data buffer.</returns>
    public static Tpm2bData Create(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Data too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bData(storage, bytes.Length);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && this != EmptyInstance)
        {
            storage?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_DATA({length} bytes)";
}