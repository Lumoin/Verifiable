using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// RSA public key buffer (TPM2B_PUBLIC_KEY_RSA).
/// </summary>
/// <remarks>
/// <para>
/// This structure holds the modulus (n) of an RSA public key.
/// The maximum size is determined by the largest RSA key size supported
/// by the TPM (typically 4096 bits = 512 bytes).
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                              // Size of the buffer in bytes.
///     BYTE buffer[MAX_RSA_KEY_BYTES];           // The RSA modulus.
/// } TPM2B_PUBLIC_KEY_RSA;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.2.4.5.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct Tpm2bPublicKeyRsa: IDisposable, IEquatable<Tpm2bPublicKeyRsa>
{
    /// <summary>
    /// Maximum RSA key size in bytes (4096 bits).
    /// </summary>
    public const int MaxRsaKeyBytes = 512;

    private readonly IMemoryOwner<byte>? memoryOwner;
    private readonly ReadOnlyMemory<byte> buffer;

    /// <summary>
    /// Initializes a new instance with owned memory.
    /// </summary>
    private Tpm2bPublicKeyRsa(IMemoryOwner<byte>? owner, ReadOnlyMemory<byte> data)
    {
        memoryOwner = owner;
        buffer = data;
    }

    /// <summary>
    /// Gets the size of the public key in bytes.
    /// </summary>
    public int Size => buffer.Length;

    /// <summary>
    /// Gets the public key data (RSA modulus).
    /// </summary>
    public ReadOnlySpan<byte> Buffer => buffer.Span;

    /// <summary>
    /// Gets whether this buffer is empty.
    /// </summary>
    public bool IsEmpty => buffer.IsEmpty;

    /// <summary>
    /// Gets the serialized size in bytes.
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Size;

    /// <summary>
    /// Writes this structure to a writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)Size);
        writer.WriteBytes(Buffer);
    }

    /// <summary>
    /// Parses an RSA public key from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The parsed RSA public key.</returns>
    public static Tpm2bPublicKeyRsa Parse(ref TpmReader reader, MemoryPool<byte>? pool = null)
    {
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxRsaKeyBytes)
        {
            throw new InvalidOperationException($"RSA public key size {size} exceeds maximum {MaxRsaKeyBytes}.");
        }

        pool ??= MemoryPool<byte>.Shared;
        var owner = pool.Rent(size);
        reader.ReadBytes(size).CopyTo(owner.Memory.Span);
        return new Tpm2bPublicKeyRsa(owner, owner.Memory[..size]);
    }

    /// <summary>
    /// Creates an RSA public key from the given data.
    /// </summary>
    /// <param name="modulus">The RSA modulus.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The RSA public key.</returns>
    public static Tpm2bPublicKeyRsa Create(ReadOnlySpan<byte> modulus, MemoryPool<byte>? pool = null)
    {
        if(modulus.Length > MaxRsaKeyBytes)
        {
            throw new ArgumentException($"RSA modulus size {modulus.Length} exceeds maximum {MaxRsaKeyBytes}.", nameof(modulus));
        }

        if(modulus.IsEmpty)
        {
            return Empty;
        }

        pool ??= MemoryPool<byte>.Shared;
        var owner = pool.Rent(modulus.Length);
        modulus.CopyTo(owner.Memory.Span);
        return new Tpm2bPublicKeyRsa(owner, owner.Memory[..modulus.Length]);
    }

    /// <summary>
    /// Gets an empty RSA public key buffer.
    /// </summary>
    public static Tpm2bPublicKeyRsa Empty { get; } = new(null, ReadOnlyMemory<byte>.Empty);

    /// <inheritdoc/>
    public void Dispose()
    {
        memoryOwner?.Dispose();
    }

    /// <inheritdoc/>
    public bool Equals(Tpm2bPublicKeyRsa other) => buffer.Span.SequenceEqual(other.buffer.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Tpm2bPublicKeyRsa other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = new();
        hash.AddBytes(buffer.Span);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(Tpm2bPublicKeyRsa left, Tpm2bPublicKeyRsa right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(Tpm2bPublicKeyRsa left, Tpm2bPublicKeyRsa right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPM2B_PUBLIC_KEY_RSA({Size} bytes)";
}