using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// ML-DSA signature buffer (TPM2B_SIGNATURE_MLDSA).
/// </summary>
/// <remarks>
/// <para>
/// Contains an ML-DSA signature according to FIPS 204.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                         // Size of the buffer.
///     BYTE   buffer[size]{:MAX_MLDSA_SIG_SIZE}; // The signature.
/// } TPM2B_SIGNATURE_MLDSA;
/// </code>
/// <para>
/// MAX_MLDSA_SIG_SIZE is the maximum signature size for any ML-DSA
/// parameter set supported by the TPM.
/// </para>
/// <para>
/// Note: Unlike other signature types (RSA, ECC), ML-DSA signatures do not
/// include a hash algorithm field because there is no choice of hash algorithm
/// in the signature's metadata.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.3.4, Table 216 (v1.85).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct Tpm2bSignatureMlDsa: IDisposable, IEquatable<Tpm2bSignatureMlDsa>
{
    /// <summary>
    /// Maximum signature size for ML-DSA-87 (largest parameter set).
    /// </summary>
    public const int MaxMlDsaSigSize = 4627;

    private readonly IMemoryOwner<byte>? memoryOwner;
    private readonly ReadOnlyMemory<byte> buffer;

    /// <summary>
    /// Gets the signature data.
    /// </summary>
    public ReadOnlySpan<byte> Buffer => buffer.Span;

    /// <summary>
    /// Gets the size of the signature.
    /// </summary>
    public int Size => buffer.Length;

    /// <summary>
    /// Gets whether this buffer is empty.
    /// </summary>
    public bool IsEmpty => buffer.IsEmpty;

    private Tpm2bSignatureMlDsa(IMemoryOwner<byte>? owner, ReadOnlyMemory<byte> data)
    {
        memoryOwner = owner;
        buffer = data;
    }

    /// <summary>
    /// Creates a new ML-DSA signature buffer from existing data.
    /// </summary>
    /// <param name="signature">The signature data.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The signature buffer.</returns>
    public static Tpm2bSignatureMlDsa Create(ReadOnlySpan<byte> signature, MemoryPool<byte>? pool = null)
    {
        if(signature.Length > MaxMlDsaSigSize)
        {
            throw new ArgumentException($"Signature size {signature.Length} exceeds maximum {MaxMlDsaSigSize}.", nameof(signature));
        }

        if(signature.IsEmpty)
        {
            return Empty();
        }

        pool ??= MemoryPool<byte>.Shared;
        var owner = pool.Rent(signature.Length);
        signature.CopyTo(owner.Memory.Span);
        return new Tpm2bSignatureMlDsa(owner, owner.Memory[..signature.Length]);
    }

    /// <summary>
    /// Creates an empty ML-DSA signature buffer.
    /// </summary>
    /// <returns>An empty buffer.</returns>
    public static Tpm2bSignatureMlDsa Empty() => new(null, ReadOnlyMemory<byte>.Empty);

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize() => sizeof(ushort) + buffer.Length;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)buffer.Length);
        writer.WriteBytes(buffer.Span);
    }

    /// <summary>
    /// Parses an ML-DSA signature from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The parsed signature.</returns>
    public static Tpm2bSignatureMlDsa Parse(ref TpmReader reader, MemoryPool<byte>? pool = null)
    {
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty();
        }

        if(size > MaxMlDsaSigSize)
        {
            throw new InvalidOperationException($"ML-DSA signature size {size} exceeds maximum {MaxMlDsaSigSize}.");
        }

        pool ??= MemoryPool<byte>.Shared;
        var owner = pool.Rent(size);
        reader.ReadBytes(size).CopyTo(owner.Memory.Span);
        return new Tpm2bSignatureMlDsa(owner, owner.Memory[..size]);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        memoryOwner?.Dispose();
    }

    /// <inheritdoc/>
    public bool Equals(Tpm2bSignatureMlDsa other) => buffer.Span.SequenceEqual(other.buffer.Span);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Tpm2bSignatureMlDsa other && Equals(other);

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
    public static bool operator ==(Tpm2bSignatureMlDsa left, Tpm2bSignatureMlDsa right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(Tpm2bSignatureMlDsa left, Tpm2bSignatureMlDsa right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPM2B_SIGNATURE_MLDSA({Size} bytes)";
}