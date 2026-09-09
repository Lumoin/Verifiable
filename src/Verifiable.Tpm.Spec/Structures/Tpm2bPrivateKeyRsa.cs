using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_PRIVATE_KEY_RSA - a sized buffer holding a prime factor of an RSA private key.
/// </summary>
/// <remarks>
/// <para>
/// This structure carries the <c>rsa</c> arm of <c>TPMU_SENSITIVE_COMPOSITE</c>: a prime factor of the public
/// modulus, prefixed with a 16-bit size field. TPM 2.0 Library Part 2, clause 11.2.4.8, Table 196 states: "This
/// sized buffer holds the largest RSA prime number supported by the TPM. All primes are required to have
/// exactly half the number of significant bits as the public modulus, and the square of each prime is required
/// to have the same number of significant bits as the public modulus." The exact-half-width rule is judged by
/// the command that installs the value (Part 4 <c>CryptValidateKeys</c>, TPM_RC_KEY_SIZE), not by this carrier,
/// which enforces only the structural bound.
/// </para>
/// <para>
/// <strong>Wire format (big-endian):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: size (UINT16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: buffer - the prime factor, big-endian.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.4.8, Table 196.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bPrivateKeyRsa: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// The largest prime factor a <c>TPM2B_PRIVATE_KEY_RSA</c> buffer may carry: <c>RSA_PRIVATE_SIZE</c>, half
    /// of <c>MAX_RSA_KEY_BYTES</c> (TPM 2.0 Library Part 2, clause 11.2.4.8's "exactly half the number of
    /// significant bits as the public modulus"), which this library takes as 256 octets for a 4096-bit modulus.
    /// A wider value is not a well-formed <c>TPM2B_PRIVATE_KEY_RSA</c> and is refused with <c>TPM_RC_SIZE</c>.
    /// </summary>
    public const int MaxSize = 256;

    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static Tpm2bPrivateKeyRsa EmptyInstance { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Gets an empty RSA private-key prime factor.
    /// </summary>
    public static Tpm2bPrivateKeyRsa Empty => EmptyInstance;

    /// <summary>
    /// Initializes a new RSA private-key prime factor with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the prime's octets.</param>
    public Tpm2bPrivateKeyRsa(IMemoryOwner<byte> storage): base(storage, TpmTags.PrivateKeyFactor)
    {
    }

    /// <summary>
    /// Gets the length of the prime factor in bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets a value indicating whether this prime factor is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Gets the serialized size (2-byte size prefix + data).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Length;

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Parses an RSA private-key prime factor from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The rental is <see cref="AllocationKind.Pinned"/>: the octets are a private-key component, and pinning
    /// keeps them out of relocatable memory the runtime could copy without clearing, the same rule
    /// <see cref="Tpm2bSensitiveData.Parse(ref TpmReader, BaseMemoryPool)"/> and <see cref="Tpm2bAuth.Parse(ref TpmReader, BaseMemoryPool)"/> apply.
    /// </remarks>
    /// <param name="reader">The reader positioned at the prime factor.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed prime factor.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>, which a TPM answers with <c>TPM_RC_SIZE</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>; checked before any storage is rented, so a truncated frame orphans nothing.</exception>
    public static Tpm2bPrivateKeyRsa Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort length = reader.ReadUInt16();

        if(length == 0)
        {
            return EmptyInstance;
        }

        if(length > MaxSize)
        {
            throw new InvalidOperationException($"RSA private-key prime factor size {length} exceeds maximum {MaxSize}.");
        }

        if(length > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), (int)length, $"RSA private-key prime factor size {length} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(length, AllocationKind.Pinned);
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(length);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, length));

        return new Tpm2bPrivateKeyRsa(storage);
    }

    /// <summary>
    /// Creates an RSA private-key prime factor from the specified bytes.
    /// </summary>
    /// <param name="bytes">The prime's octets, big-endian.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created prime factor.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bPrivateKeyRsa Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"RSA private-key prime factor too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length, AllocationKind.Pinned);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bPrivateKeyRsa(storage);
    }

    /// <summary>The debugger text this type's <see cref="DebuggerDisplayAttribute"/> names: the structure and the prime factor's width.</summary>
    private string DebuggerDisplay => IsEmpty ? "TPM2B_PRIVATE_KEY_RSA(empty)" : $"TPM2B_PRIVATE_KEY_RSA({Length} bytes)";
}
