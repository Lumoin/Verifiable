using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Compression;

namespace Verifiable.Core.StatusList;

/// <summary>
/// A compressed bit array containing status information for Referenced Tokens.
/// </summary>
/// <remarks>
/// <para>
/// A Status List is the core data structure defined by the Token Status List specification
/// (draft-ietf-oauth-status-list). It stores status values for multiple Referenced Tokens
/// in a compressed byte array, where each entry occupies a fixed number of bits.
/// </para>
/// <para>
/// Key characteristics:
/// </para>
/// <list type="bullet">
///   <item><description>Indices start at 0 and increase sequentially.</description></item>
///   <item><description>Bits are packed from least significant bit (0) to most significant bit (7) within each byte.</description></item>
///   <item><description>The byte array is compressed using DEFLATE with the ZLIB data format.</description></item>
///   <item><description>Implementations should use the highest available compression level.</description></item>
/// </list>
/// <para>
/// Memory is managed through <see cref="IMemoryOwner{T}"/> from a <see cref="MemoryPool{T}"/>,
/// supporting <see cref="SensitiveMemoryPool"/> for proper cryptographic material handling.
/// Callers must dispose this instance to return memory to the pool.
/// </para>
/// <para>
/// Example usage:
/// </para>
/// <code>
/// using var list = StatusList.Create(1000, StatusListBitSize.OneBit, pool);
/// list[42] = StatusTypes.Invalid;
/// byte status = list[42];
/// byte[] compressed = list.Compress();
/// </code>
/// </remarks>
[DebuggerDisplay("StatusList[Bits={BitSize}, Capacity={Capacity}]")]
public sealed class StatusList: IDisposable, IEquatable<StatusList>
{
    private IMemoryOwner<byte>? memoryOwner;
    private readonly int byteCount;
    private bool disposed;

    /// <summary>
    /// Gets the number of bits used per status entry.
    /// </summary>
    public StatusListBitSize BitSize { get; }

    /// <summary>
    /// Gets the total number of status entries this list can hold.
    /// </summary>
    public int Capacity { get; }

    /// <summary>
    /// Gets or sets an optional URI to the Status List Aggregation endpoint.
    /// </summary>
    /// <remarks>
    /// This is settable to allow converters and factory methods to attach the URI
    /// after construction, since the aggregation URI is metadata rather than
    /// cryptographic state.
    /// </remarks>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings", Justification = "The specification defines this as a string value serialized directly in JSON and CBOR formats.")]
    public string? AggregationUri { get; set; }

    /// <summary>
    /// Gets or sets the status value at the specified index.
    /// </summary>
    /// <param name="index">The zero-based index of the Referenced Token.</param>
    /// <returns>The status value at the given index.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="index"/> is outside the valid range
    /// or the assigned value exceeds the maximum for the current bit size.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown when this instance has been disposed.</exception>
    public byte this[int index]
    {
        get => Get(index);
        set => Set(index, value);
    }

    private StatusList(IMemoryOwner<byte> memoryOwner, StatusListBitSize bitSize, int capacity, int byteCount)
    {
        this.memoryOwner = memoryOwner;
        this.byteCount = byteCount;
        BitSize = bitSize;
        Capacity = capacity;
    }

    /// <summary>
    /// Creates a new Status List with the specified capacity and bit size,
    /// with all entries initialized to <see cref="StatusTypes.Valid"/> (0x00).
    /// </summary>
    /// <param name="capacity">The number of status entries. Must be positive.</param>
    /// <param name="bitSize">The number of bits per entry.</param>
    /// <param name="pool">
    /// The memory pool to allocate from. Should return exact-size buffers.
    /// Use <see cref="SensitiveMemoryPool"/> for proper disposal and zeroing.
    /// </param>
    /// <returns>A new <see cref="StatusList"/> instance.</returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="capacity"/> is not positive or
    /// <paramref name="bitSize"/> is not a valid value.
    /// </exception>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    public static StatusList Create(int capacity, StatusListBitSize bitSize, MemoryPool<byte> pool)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        ValidateBitSize(bitSize);
        ArgumentNullException.ThrowIfNull(pool);

        int bits = (int)bitSize;
        int byteCount = (capacity * bits + 7) / 8;
        IMemoryOwner<byte> owner = pool.Rent(byteCount);

        //Zero out for clean initial state.
        owner.Memory.Span[..byteCount].Clear();

        return new StatusList(owner, bitSize, capacity, byteCount);
    }

    /// <summary>
    /// Creates a Status List by decompressing ZLIB-compressed data.
    /// </summary>
    /// <param name="compressedData">The ZLIB-compressed byte array.</param>
    /// <param name="bitSize">The number of bits per entry.</param>
    /// <param name="pool">
    /// The memory pool to allocate the decompressed data into.
    /// Use <see cref="SensitiveMemoryPool"/> for proper disposal and zeroing.
    /// </param>
    /// <returns>A new <see cref="StatusList"/> instance with the decompressed data.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="compressedData"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="compressedData"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="bitSize"/> is not a valid value.</exception>
    public static StatusList FromCompressed(ReadOnlySpan<byte> compressedData, StatusListBitSize bitSize, MemoryPool<byte> pool)
    {
        if(compressedData.IsEmpty)
        {
            throw new ArgumentException("Compressed data must not be empty.", nameof(compressedData));
        }

        ValidateBitSize(bitSize);
        ArgumentNullException.ThrowIfNull(pool);

        byte[] decompressed = Decompress(compressedData);
        int bits = (int)bitSize;
        int capacity = decompressed.Length * 8 / bits;

        IMemoryOwner<byte> owner = pool.Rent(decompressed.Length);
        decompressed.CopyTo(owner.Memory.Span);

        return new StatusList(owner, bitSize, capacity, decompressed.Length);
    }

    /// <summary>
    /// Creates a Status List from an uncompressed byte array.
    /// </summary>
    /// <param name="rawData">The uncompressed byte array containing status values.</param>
    /// <param name="bitSize">The number of bits per entry.</param>
    /// <param name="pool">
    /// The memory pool to copy the data into.
    /// Use <see cref="SensitiveMemoryPool"/> for proper disposal and zeroing.
    /// </param>
    /// <returns>A new <see cref="StatusList"/> instance.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when <paramref name="rawData"/> is empty.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="bitSize"/> is not a valid value.</exception>
    public static StatusList FromRaw(ReadOnlySpan<byte> rawData, StatusListBitSize bitSize, MemoryPool<byte> pool)
    {
        if(rawData.IsEmpty)
        {
            throw new ArgumentException("Raw data must not be empty.", nameof(rawData));
        }

        ValidateBitSize(bitSize);
        ArgumentNullException.ThrowIfNull(pool);

        int bits = (int)bitSize;
        int capacity = rawData.Length * 8 / bits;

        IMemoryOwner<byte> owner = pool.Rent(rawData.Length);
        rawData.CopyTo(owner.Memory.Span);

        return new StatusList(owner, bitSize, capacity, rawData.Length);
    }

    /// <summary>
    /// Gets the status value at the specified index.
    /// </summary>
    /// <param name="index">The zero-based index of the Referenced Token.</param>
    /// <returns>The status value at the given index.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when <paramref name="index"/> is outside the valid range.</exception>
    /// <exception cref="ObjectDisposedException">Thrown when this instance has been disposed.</exception>
    public byte Get(int index)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, Capacity);

        ReadOnlySpan<byte> data = memoryOwner!.Memory.Span;
        int bits = (int)BitSize;
        int entriesPerByte = 8 / bits;
        int byteIndex = index / entriesPerByte;
        int bitOffset = (index % entriesPerByte) * bits;
        byte mask = (byte)((1 << bits) - 1);

        return (byte)((data[byteIndex] >> bitOffset) & mask);
    }

    /// <summary>
    /// Sets the status value at the specified index.
    /// </summary>
    /// <param name="index">The zero-based index of the Referenced Token.</param>
    /// <param name="value">The status value to set. Must fit within the configured bit size.</param>
    /// <exception cref="ArgumentOutOfRangeException">
    /// Thrown when <paramref name="index"/> is outside the valid range
    /// or <paramref name="value"/> exceeds the maximum for the current bit size.
    /// </exception>
    /// <exception cref="ObjectDisposedException">Thrown when this instance has been disposed.</exception>
    public void Set(int index, byte value)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentOutOfRangeException.ThrowIfNegative(index);
        ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(index, Capacity);

        int bits = (int)BitSize;
        byte maxValue = (byte)((1 << bits) - 1);
        if(value > maxValue)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                value,
                $"Status value must not exceed {maxValue} for {bits}-bit entries.");
        }

        Span<byte> data = memoryOwner!.Memory.Span;
        int entriesPerByte = 8 / bits;
        int byteIndex = index / entriesPerByte;
        int bitOffset = (index % entriesPerByte) * bits;

        data[byteIndex] = (byte)((data[byteIndex] & ~(maxValue << bitOffset)) | (value << bitOffset));
    }

    /// <summary>
    /// Compresses the underlying byte array using DEFLATE with the ZLIB data format.
    /// </summary>
    /// <param name="compressionLevel">
    /// The compression level to use. The specification recommends the highest available level.
    /// </param>
    /// <returns>The ZLIB-compressed byte array.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when this instance has been disposed.</exception>
    public byte[] Compress(CompressionLevel compressionLevel = CompressionLevel.SmallestSize)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        ReadOnlySpan<byte> data = memoryOwner!.Memory.Span[..byteCount];
        using var output = new MemoryStream();
        using(var zlib = new ZLibStream(output, compressionLevel))
        {
            zlib.Write(data);
        }

        return output.ToArray();
    }


    /// <summary>
    /// Releases the memory back to the pool.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            memoryOwner?.Dispose();
            memoryOwner = null;
            disposed = true;
        }
    }

    
    /// <summary>
    /// Gets the underlying data as a read-only span without copying.
    /// </summary>
    /// <returns>A read-only span over the raw status data.</returns>
    /// <exception cref="ObjectDisposedException">Thrown when this instance has been disposed.</exception>
    public ReadOnlySpan<byte> AsSpan()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return memoryOwner!.Memory.Span[..byteCount];
    }

    /// <inheritdoc/>
    public bool Equals(StatusList? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(BitSize != other.BitSize || Capacity != other.Capacity)
        {
            return false;
        }

        if(disposed || other.disposed)
        {
            return false;
        }

        return memoryOwner!.Memory.Span[..byteCount].SequenceEqual(other.memoryOwner!.Memory.Span[..other.byteCount])
            && string.Equals(AggregationUri, other.AggregationUri, StringComparison.Ordinal);
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj)
    {
        return Equals(obj as StatusList);
    }

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        if(disposed)
        {
            return 0;
        }

        var hash = new HashCode();
        hash.Add(BitSize);
        hash.Add(Capacity);
        hash.Add(AggregationUri);
        hash.AddBytes(memoryOwner!.Memory.Span[..byteCount]);

        return hash.ToHashCode();
    }

    /// <summary>
    /// Determines whether two <see cref="StatusList"/> instances are equal.
    /// </summary>
    public static bool operator ==(StatusList? left, StatusList? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two <see cref="StatusList"/> instances are not equal.
    /// </summary>
    public static bool operator !=(StatusList? left, StatusList? right)
    {
        return !(left == right);
    }


    private static byte[] Decompress(ReadOnlySpan<byte> compressedData)
    {
        using var input = new MemoryStream(compressedData.ToArray());
        using var zlib = new ZLibStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        zlib.CopyTo(output);

        return output.ToArray();
    }


    private static void ValidateBitSize(StatusListBitSize bitSize)
    {
        if(bitSize is not (StatusListBitSize.OneBit or StatusListBitSize.TwoBits or StatusListBitSize.FourBits or StatusListBitSize.EightBits))
        {
            throw new ArgumentOutOfRangeException(nameof(bitSize), bitSize, "Bit size must be 1, 2, 4, or 8.");
        }
    }
}