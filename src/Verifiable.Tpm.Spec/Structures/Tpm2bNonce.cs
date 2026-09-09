using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_NONCE - a sized buffer for nonce values.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds variable-length nonce data prefixed with a 16-bit size field.
/// A nonce is a random value used to provide freshness in session protocols.
/// </para>
/// <para>
/// <strong>Wire format (big-endian):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the nonce data.</description></item>
/// </list>
/// <para>
/// <strong>Session usage:</strong>
/// </para>
/// <para>
/// Nonces are used in HMAC session protocols for replay protection. Each command
/// includes a new nonceCaller, and each response includes a new nonceTPM. The nonces
/// are included in the HMAC computation but without their size fields.
/// </para>
/// <para>
/// <strong>Empty nonces:</strong> Use <see cref="CreateEmpty"/> to obtain a shared
/// empty instance backed by <see cref="EmptyMemoryOwner"/>. This avoids pool allocations
/// for zero-length buffers.
/// </para>
/// <para>
/// See TPM 2.0 Library Part 1, clause 16.6.3 - Session Nonces.
/// See TPM 2.0 Library Part 2, clause 10.3.4.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bNonce: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// The largest nonce a <c>TPM2B_NONCE</c> buffer may carry: <c>sizeof(TPMU_HA)</c>, 64 octets. Table 92
    /// defines the type as a <c>TPM2B_DIGEST</c> whose "size limited to the same as the digest structure" (TPM
    /// 2.0 Library Part 2, clause 10.3.4, page 134), and that structure's own table bounds its buffer field at
    /// <c>buffer[size]{:sizeof(TPMU_HA)}</c> (clause 10.3.2, Table 90, page 134). The same clause states what a
    /// wider value answers with: "As with all sized buffers, the size is checked to see if it is within the
    /// prescribed range. If not, the response code is TPM_RC_SIZE", and its note adds that "For any structure,
    /// like the one below, that contains an implied size check, it is implied that TPM_RC_SIZE is a possible
    /// response code and the response code will not be listed in the table". The bound is the hash union's
    /// width, never the width of whatever session hash algorithm a nonce happens to serve.
    /// </summary>
    public const int MaxSize = 64;

    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static Tpm2bNonce EmptyInstance { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Initializes a new nonce with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the nonce bytes.</param>
    public Tpm2bNonce(IMemoryOwner<byte> storage) : base(storage, TpmTags.Nonce)
    {
    }

    /// <summary>
    /// Gets the size of the nonce data in bytes.
    /// </summary>
    public int Size => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets a value indicating whether this nonce is empty.
    /// </summary>
    public bool IsEmpty => Size == 0;

    /// <summary>
    /// Parses a nonce from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the nonce.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed nonce.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>, which a TPM answers with <c>TPM_RC_SIZE</c>.</exception>
    public static Tpm2bNonce Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();
        if(size == 0)
        {
            return EmptyInstance;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Nonce size {size} exceeds maximum {MaxSize}.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);

        //Copy nonce bytes into owned storage.
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(size);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bNonce(storage);
    }

    /// <summary>
    /// Writes this nonce to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Gets the serialized size (2-byte length prefix + data).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Size;

    /// <summary>
    /// Gets the shared empty nonce, for contexts with no pool in scope — the same dispose-immune instance
    /// <see cref="CreateEmpty"/> returns, mirroring <see cref="Tpm2bAuth.Empty"/>.
    /// </summary>
    public static Tpm2bNonce Empty => EmptyInstance;

    /// <summary>
    /// Creates an empty nonce.
    /// </summary>
    /// <param name="pool">The memory pool (unused for empty nonces).</param>
    /// <returns>An empty nonce.</returns>
    public static Tpm2bNonce CreateEmpty(BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        return EmptyInstance;
    }

    /// <summary>
    /// Creates a nonce from the specified bytes.
    /// </summary>
    /// <param name="bytes">The nonce bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created nonce.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bNonce Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Nonce too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);
        return new Tpm2bNonce(storage);
    }

    /// <summary>
    /// Creates a nonce with random data.
    /// </summary>
    /// <param name="length">The length of the nonce in bytes.</param>
    /// <param name="rng">The entropy source the nonce bytes are drawn from.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>A nonce filled with random data.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Length is zero or negative, or greater than <see cref="MaxSize"/>.</exception>
    public static Tpm2bNonce CreateRandom(int length, FillEntropyDelegate rng, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(rng);
        ArgumentNullException.ThrowIfNull(pool);
        if(length <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Nonce size must be greater than zero.");
        }

        if(length > MaxSize)
        {
            throw new ArgumentOutOfRangeException(nameof(length), $"Nonce size must be no greater than {MaxSize} bytes.");
        }

        IMemoryOwner<byte> storage = pool.Rent(length);
        rng(storage.Memory.Span.Slice(0, length));
        return new Tpm2bNonce(storage);
    }

    private string DebuggerDisplay => $"TPM2B_NONCE({Size} bytes)";
}
