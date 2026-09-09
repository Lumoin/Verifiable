using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// ML-DSA public key buffer (TPM2B_PUBLIC_KEY_MLDSA).
/// </summary>
/// <remarks>
/// <para>
/// Contains an encoded ML-DSA public key according to Algorithm 22
/// (pkEncode) of FIPS 204.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the buffer.
///     BYTE   buffer[size]{:MAX_MLDSA_PUB_SIZE}; // The public key.
/// } TPM2B_PUBLIC_KEY_MLDSA;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.7.3, Table 210.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct Tpm2bPublicKeyMlDsa: IDisposable, IEquatable<Tpm2bPublicKeyMlDsa>
{
    /// <summary>
    /// Maximum public key size for ML-DSA-87 (largest parameter set).
    /// </summary>
    public const int MaxMlDsaPubSize = 2592;

    private IMemoryOwner<byte>? MemoryOwner { get; }
    private ReadOnlyMemory<byte> RawBuffer { get; }

    /// <summary>
    /// Initializes a new instance with owned memory.
    /// </summary>
    private Tpm2bPublicKeyMlDsa(IMemoryOwner<byte>? owner, ReadOnlyMemory<byte> data)
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
    /// Creates a new ML-DSA public key buffer from existing data.
    /// </summary>
    /// <param name="publicKey">The public key data.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The public key buffer.</returns>
    public static Tpm2bPublicKeyMlDsa Create(ReadOnlySpan<byte> publicKey, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(publicKey.Length > MaxMlDsaPubSize)
        {
            throw new ArgumentException($"Public key size {publicKey.Length} exceeds maximum {MaxMlDsaPubSize}.", nameof(publicKey));
        }

        if(publicKey.IsEmpty)
        {
            return Empty;
        }

        var owner = pool.Rent(publicKey.Length);
        publicKey.CopyTo(owner.Memory.Span);
        return new Tpm2bPublicKeyMlDsa(owner, owner.Memory[..publicKey.Length]);
    }

    /// <summary>
    /// Gets an empty ML-DSA public key buffer.
    /// </summary>
    public static Tpm2bPublicKeyMlDsa Empty { get; } = new(null, ReadOnlyMemory<byte>.Empty);

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
    /// Parses an ML-DSA public key from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The parsed public key.</returns>
    public static Tpm2bPublicKeyMlDsa Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxMlDsaPubSize)
        {
            throw new InvalidOperationException($"ML-DSA public key size {size} exceeds maximum {MaxMlDsaPubSize}.");
        }

        var owner = pool.Rent(size);
        reader.ReadBytes(size).CopyTo(owner.Memory.Span);
        return new Tpm2bPublicKeyMlDsa(owner, owner.Memory[..size]);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        MemoryOwner?.Dispose();
    }

    /// <inheritdoc/>
    public bool Equals(Tpm2bPublicKeyMlDsa other) => RawBuffer.Span.SequenceEqual(other.RawBuffer.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Tpm2bPublicKeyMlDsa other && Equals(other);

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
    public static bool operator ==(Tpm2bPublicKeyMlDsa left, Tpm2bPublicKeyMlDsa right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(Tpm2bPublicKeyMlDsa left, Tpm2bPublicKeyMlDsa right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPM2B_PUBLIC_KEY_MLDSA({Size} bytes)";
}
