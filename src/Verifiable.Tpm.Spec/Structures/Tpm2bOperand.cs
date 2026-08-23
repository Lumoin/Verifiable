using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Sized buffer for an NV Index comparison operand (TPM2B_OPERAND).
/// </summary>
/// <remarks>
/// <para>
/// Carries the operand for <c>TPM2_PolicyNV()</c> and <c>TPM2_NV_SetBits()</c>-adjacent comparisons against an
/// NV Index location. Part 2, Table 96 defines <c>TPM2B_OPERAND</c> as "size limited to the same as the digest
/// structure" — Table 92's <c>TPM2B_DIGEST</c> bound, <c>buffer[size]{{:sizeof(TPMU_HA)}}</c>, the largest
/// digest this library's <c>TPMU_HA</c> union can hold. That largest digest is 64 octets (SHA-512;
/// <see cref="Verifiable.Tpm.Spec.Constants.TpmAlgIdExtensions.GetDigestSize"/>), so <see cref="MaxSize"/> is 64.
/// The docs name <c>TPM2B_OPERAND</c> a distinct type rather than an alias of <c>TPM2B_DIGEST</c>, so this
/// carrier is its own type rather than reusing <see cref="Tpm2bDigest"/>.
/// </para>
/// <para>
/// The content is a comparison operand, not secret key material, so this carrier holds no
/// <see cref="Verifiable.Cryptography.SensitiveMemory"/> tag; it follows the hand-rolled pooled shape of
/// <see cref="Tpm2bName"/> and <see cref="Tpm2bData"/>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of the operand, at most MaxSize.
///     BYTE buffer[size];                       // The operand.
/// } TPM2B_OPERAND;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.4.6, Table 96.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bOperand: IDisposable
{
    /// <summary>
    /// Maximum size of the operand: the largest digest this library supports (64 octets, SHA-512), matching
    /// <c>TPM2B_DIGEST</c>'s bound per Part 2, Table 96's "size limited to the same as the digest structure".
    /// </summary>
    public const int MaxSize = 64;

    private static Tpm2bOperand EmptyInstance { get; } = new();

    private IMemoryOwner<byte>? Storage { get; }
    private bool disposed;

    /// <summary>
    /// Initializes an empty operand.
    /// </summary>
    private Tpm2bOperand()
    {
        Storage = null;
        Length = 0;
    }

    /// <summary>
    /// Initializes a new operand with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the operand bytes.</param>
    /// <param name="length">The actual length of the operand.</param>
    private Tpm2bOperand(IMemoryOwner<byte> storage, int length)
    {
        this.Storage = storage;
        this.Length = length;
    }

    /// <summary>
    /// Gets an empty operand.
    /// </summary>
    public static Tpm2bOperand Empty => EmptyInstance;

    /// <summary>
    /// Gets whether this operand is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the length of the operand in bytes.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets the operand data as a read-only span.
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
    /// Gets the operand data as read-only memory that aliases this instance's pooled storage — for a
    /// borrowing consumer, valid until <see cref="Dispose"/> and never copied into an untracked array.
    /// </summary>
    /// <returns>The operand bytes.</returns>
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
    /// Parses an operand from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed operand.</returns>
    /// <exception cref="InvalidOperationException">The wire size exceeds <see cref="MaxSize"/> (<c>TPM_RC_SIZE</c>).</exception>
    public static Tpm2bOperand Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Operand size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(storage.Memory.Span.Slice(0, size));

            return new Tpm2bOperand(storage, size);
        }
        catch
        {
            storage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Creates an operand from the specified bytes.
    /// </summary>
    /// <param name="bytes">The operand bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created operand.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bOperand Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Operand too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bOperand(storage, bytes.Length);
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

    private string DebuggerDisplay => $"TPM2B_OPERAND({Length} bytes)";
}
