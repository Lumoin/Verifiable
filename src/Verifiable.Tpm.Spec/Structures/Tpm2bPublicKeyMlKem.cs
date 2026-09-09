using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// ML-KEM public key buffer (TPM2B_PUBLIC_KEY_MLKEM).
/// </summary>
/// <remarks>
/// <para>
/// Contains an encoded ML-KEM public key according to Algorithm 19
/// (ML-KEM.KeyGen) of FIPS 203.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the buffer.
///     BYTE   buffer[size]{:MAX_MLKEM_PUB_SIZE}; // The public key.
/// } TPM2B_PUBLIC_KEY_MLKEM;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.6.2, Table 206.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct Tpm2bPublicKeyMlKem: IDisposable, IEquatable<Tpm2bPublicKeyMlKem>
{
    /// <summary>
    /// Maximum public key size for ML-KEM-1024 (largest parameter set).
    /// </summary>
    public const int MaxMlKemPubSize = 1568;

    private IMemoryOwner<byte>? MemoryOwner { get; }
    private ReadOnlyMemory<byte> RawBuffer { get; }

    /// <summary>
    /// Initializes a new instance with owned memory.
    /// </summary>
    private Tpm2bPublicKeyMlKem(IMemoryOwner<byte>? owner, ReadOnlyMemory<byte> data)
    {
        MemoryOwner = owner;
        RawBuffer = data;
    }

    /// <summary>
    /// Gets the public key data.
    /// </summary>
    public ReadOnlySpan<byte> Buffer => RawBuffer.Span;

    /// <summary>
    /// Gets the size of the public key.
    /// </summary>
    public int Size => RawBuffer.Length;

    /// <summary>
    /// Gets whether this buffer is empty.
    /// </summary>
    public bool IsEmpty => RawBuffer.IsEmpty;

    /// <summary>
    /// Creates a new ML-KEM public key buffer from existing data.
    /// </summary>
    /// <param name="publicKey">The public key data.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The public key buffer.</returns>
    public static Tpm2bPublicKeyMlKem Create(ReadOnlySpan<byte> publicKey, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(publicKey.Length > MaxMlKemPubSize)
        {
            throw new ArgumentException($"Public key size {publicKey.Length} exceeds maximum {MaxMlKemPubSize}.", nameof(publicKey));
        }

        if(publicKey.IsEmpty)
        {
            return Empty;
        }

        var owner = pool.Rent(publicKey.Length);
        publicKey.CopyTo(owner.Memory.Span);
        return new Tpm2bPublicKeyMlKem(owner, owner.Memory[..publicKey.Length]);
    }

    /// <summary>
    /// Gets an empty ML-KEM public key buffer.
    /// </summary>
    public static Tpm2bPublicKeyMlKem Empty { get; } = new(null, ReadOnlyMemory<byte>.Empty);

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + RawBuffer.Length;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)RawBuffer.Length);
        writer.WriteBytes(RawBuffer.Span);
    }

    /// <summary>
    /// Parses an ML-KEM public key from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The parsed public key.</returns>
    public static Tpm2bPublicKeyMlKem Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxMlKemPubSize)
        {
            throw new InvalidOperationException($"ML-KEM public key size {size} exceeds maximum {MaxMlKemPubSize}.");
        }

        var owner = pool.Rent(size);
        reader.ReadBytes(size).CopyTo(owner.Memory.Span);
        return new Tpm2bPublicKeyMlKem(owner, owner.Memory[..size]);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        MemoryOwner?.Dispose();
    }

    /// <inheritdoc/>
    public bool Equals(Tpm2bPublicKeyMlKem other) => RawBuffer.Span.SequenceEqual(other.RawBuffer.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Tpm2bPublicKeyMlKem other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.AddBytes(RawBuffer.Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(Tpm2bPublicKeyMlKem left, Tpm2bPublicKeyMlKem right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(Tpm2bPublicKeyMlKem left, Tpm2bPublicKeyMlKem right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPM2B_PUBLIC_KEY_MLKEM({Size} bytes)";
}
