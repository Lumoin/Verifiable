using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_SHARED_SECRET - a sized buffer carrying the shared secret a KEM key exchange produces.
/// </summary>
/// <remarks>
/// <para>
/// This is the response buffer <c>TPM2_Encapsulate()</c> and <c>TPM2_Decapsulate()</c> return as
/// <c>sharedSecret</c> (TPM 2.0 Library Part 3, clauses 14.10/14.11) — the KEM output the caller feeds
/// to its own key derivation, returned in the clear (the generic encrypt-session mechanism is the only
/// protection the command offers it). It is sensitive: an attacker who reads it recovers the same
/// symmetric material the legitimate caller derives from it.
/// </para>
/// <para>
/// <b>Wire format (big-endian):</b>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the shared secret octets.</description></item>
/// </list>
/// <para>
/// <b>Bound:</b> Table 100 sizes the <c>buffer</c> field as <c>{:MAX_SHARED_SECRET_SIZE}</c>, and the
/// Library leaves <c>MAX_SHARED_SECRET_SIZE</c> TPM-implementation-dependent rather than fixing a spec
/// number. <see cref="MaxSize"/> resolves that to 64 octets: the widest DHKEM this library's ECC KEM
/// path can produce is DHKEM(P-521, HKDF-SHA512) at <c>Nsecret</c> = 64 (RFC 9180 §7.1's KEM table; the
/// P-256 and P-384 suites are narrower at 32 and 48), and ML-KEM's shared secret is a fixed 32 octets
/// across all three parameter sets (FIPS 203) — so 64 covers every value this library or a conformant
/// v185 TPM emits into this field, the same digest-width-family reasoning
/// <see cref="Tpm2bDigest.MaxSize"/> applies to <c>TPMU_HA</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 10.3.12, Table 100.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bSharedSecret: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// The largest shared secret this library's <c>TPM2B_SHARED_SECRET</c> buffer carries: 64 octets,
    /// the adjudicated resolution of Table 100's TPM-dependent <c>MAX_SHARED_SECRET_SIZE</c> bound (see
    /// the type remarks for the DHKEM/ML-KEM widths this covers).
    /// </summary>
    public const int MaxSize = 64;

    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static Tpm2bSharedSecret EmptyInstance { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Gets an empty shared secret.
    /// </summary>
    public static Tpm2bSharedSecret Empty => EmptyInstance;

    /// <summary>
    /// Initializes a new shared secret with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the shared-secret bytes.</param>
    public Tpm2bSharedSecret(IMemoryOwner<byte> storage): base(storage, TpmTags.SharedSecret)
    {
    }

    /// <summary>
    /// Gets the size of the shared secret in bytes.
    /// </summary>
    public int Size => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets a value indicating whether this shared secret is empty.
    /// </summary>
    public bool IsEmpty => Size == 0;

    /// <summary>
    /// Gets the serialized size (2-byte size prefix + data).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Size;

    /// <summary>
    /// Writes this shared secret to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Parses a shared secret from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The declared size is checked against <see cref="MaxSize"/> and then against
    /// <see cref="TpmReader.Remaining"/> before any pooled buffer is rented, mirroring
    /// <see cref="Tpm2bDigest.Parse(ref TpmReader, BaseMemoryPool)"/>: a bound violation and a truncated
    /// frame are distinguishable failures, and neither ever orphans a rental.
    /// </remarks>
    /// <param name="reader">The reader positioned at the shared secret.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed shared secret.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static Tpm2bSharedSecret Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();
        if(size == 0)
        {
            return EmptyInstance;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Shared secret size {size} exceeds maximum {MaxSize}.");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), size, $"Shared secret size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size, AllocationKind.Pinned);

        //Copy shared-secret bytes into owned storage.
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(size);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bSharedSecret(storage);
    }

    /// <summary>
    /// Creates a shared secret from the specified bytes.
    /// </summary>
    /// <param name="bytes">The shared-secret bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created shared secret.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bSharedSecret Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Shared secret too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length, AllocationKind.Pinned);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bSharedSecret(storage);
    }

    /// <summary>The debugger's one-line rendering: the secret's octet count, never the octets themselves.</summary>
    private string DebuggerDisplay => $"TPM2B_SHARED_SECRET({Size} bytes)";
}
