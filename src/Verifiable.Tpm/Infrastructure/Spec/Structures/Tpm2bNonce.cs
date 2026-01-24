using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

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
/// See TPM 2.0 Part 1, Section 17.6.3 - Session Nonces.
/// See TPM 2.0 Part 2, Section 10.4.3.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bNonce: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static readonly Tpm2bNonce EmptyInstance = new(Cryptography.EmptyMemoryOwner.Instance);

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
    public static Tpm2bNonce Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ushort size = reader.ReadUInt16();
        if(size == 0)
        {
            return EmptyInstance;
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
    public int GetSerializedSize() => sizeof(ushort) + Size;

    /// <summary>
    /// Creates an empty nonce.
    /// </summary>
    /// <param name="pool">The memory pool (unused for empty nonces).</param>
    /// <returns>An empty nonce.</returns>
    public static Tpm2bNonce CreateEmpty(MemoryPool<byte> pool)
    {
        return EmptyInstance;
    }

    /// <summary>
    /// Creates a nonce from the specified bytes.
    /// </summary>
    /// <param name="bytes">The nonce bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created nonce.</returns>
    public static Tpm2bNonce Create(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);
        return new Tpm2bNonce(storage);
    }

    /// <summary>
    /// Creates a nonce with random data.
    /// </summary>
    /// <param name="length">The length of the nonce in bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>A nonce filled with random data.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Length is zero or negative.</exception>
    public static Tpm2bNonce CreateRandom(int length, MemoryPool<byte> pool)
    {
        if(length <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(length), "Nonce size must be greater than zero.");
        }

        IMemoryOwner<byte> storage = pool.Rent(length);
        System.Security.Cryptography.RandomNumberGenerator.Fill(storage.Memory.Span.Slice(0, length));
        return new Tpm2bNonce(storage);
    }

    private string DebuggerDisplay => $"TPM2B_NONCE({Size} bytes)";
}