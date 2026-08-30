using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Algorithms;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_DIGEST - a sized buffer for digest (hash) values.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds variable-length digest data prefixed with a 16-bit size field.
/// Digests are used for hash results, PCR values, cpHash/rpHash computations, and
/// random data from TPM2_GetRandom.
/// </para>
/// <para>
/// <strong>Wire format (big-endian):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the digest data.</description></item>
/// </list>
/// <para>
/// <strong>Common uses:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>Hash results from TPM2_Hash.</description></item>
///   <item><description>PCR values from TPM2_PCR_Read.</description></item>
///   <item><description>Random bytes from TPM2_GetRandom.</description></item>
///   <item><description>cpHash and rpHash for session HMAC computation.</description></item>
/// </list>
/// <para>
/// <strong>Empty digests:</strong> Use <see cref="CreateEmpty"/> to obtain a shared
/// empty instance backed by <see cref="EmptyMemoryOwner"/>. This avoids pool allocations
/// for zero-length buffers.
/// </para>
/// <para>
/// See TPM 2.0 Part 2, Section 10.3.2.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bDigest: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// The largest digest a <c>TPM2B_DIGEST</c> buffer may carry: <c>sizeof(TPMU_HA)</c>, the widest member of
    /// the hash union (64 octets, SHA-512), which is the bound Table 90 places on the buffer field
    /// (<c>buffer[size]{:sizeof(TPMU_HA)}</c>, TPM 2.0 Library Part 2, clause 10.3.2). The size prefix is not
    /// part of it — unlike <see cref="Tpm2bData.MaxSize"/>, whose table bounds the buffer by the whole
    /// <c>TPMT_HA</c> structure and therefore includes the algorithm identifier.
    /// </summary>
    public const int MaxSize = 64;

    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static Tpm2bDigest EmptyInstance { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Gets an empty digest.
    /// </summary>
    public static Tpm2bDigest Empty => EmptyInstance;

    /// <summary>Shared Zero Digest of the SHA-1 width (20 octets).</summary>
    private static Tpm2bDigest Zero160Instance { get; } = new(new ZeroDigestMemoryOwner(20));

    /// <summary>Shared Zero Digest of the truncated 192-bit width (24 octets).</summary>
    private static Tpm2bDigest Zero192Instance { get; } = new(new ZeroDigestMemoryOwner(24));

    /// <summary>Shared Zero Digest of the SHA-256 width (32 octets).</summary>
    private static Tpm2bDigest Zero256Instance { get; } = new(new ZeroDigestMemoryOwner(32));

    /// <summary>Shared Zero Digest of the SHA-384 width (48 octets).</summary>
    private static Tpm2bDigest Zero384Instance { get; } = new(new ZeroDigestMemoryOwner(48));

    /// <summary>Shared Zero Digest of the SHA-512 width (64 octets).</summary>
    private static Tpm2bDigest Zero512Instance { get; } = new(new ZeroDigestMemoryOwner(64));

    /// <summary>
    /// Gets the shared Zero Digest of <paramref name="hashAlg"/>'s width — a buffer of that many zero octets,
    /// the value TPM 2.0 Library Part 1, clause 16.7 gives an enhanced-authorization session's policyDigest
    /// before its first assertion and again after the context reset of Part 3, Section 23.2.4.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The instance is shared per width and immune to disposal, so the same one may back every unstarted and
    /// every just-reset session at once: a policyDigest is only ever replaced wholesale, never written through,
    /// and each extension hashes into a freshly rented destination. It is distinct from <see cref="Empty"/>,
    /// which carries zero octets rather than a digest-width run of zeros — an extension formula sizes its
    /// scratch from the current digest's own length, so the two produce different results and are not
    /// interchangeable.
    /// </para>
    /// <para>
    /// The admitted widths are those of <c>TPMU_HA</c> (Table 88), not those of any one consumer: the widths a
    /// policy session can actually name are the four the <c>policyDigest</c> formula sizes for (20, 32, 48 and
    /// 64 octets), and the 24-octet truncated width is here for the completeness of this Spec structure rather
    /// than for the policy path, which never reaches it.
    /// </para>
    /// </remarks>
    /// <param name="hashAlg">The hash algorithm whose digest width the Zero Digest carries.</param>
    /// <returns>The shared Zero Digest of that width.</returns>
    /// <exception cref="ArgumentException"><paramref name="hashAlg"/> names no hash algorithm, so it has no digest width.</exception>
    public static Tpm2bDigest Zero(TpmiAlgHash hashAlg) => hashAlg.DigestSize switch
    {
        20 => Zero160Instance,
        24 => Zero192Instance,
        32 => Zero256Instance,
        48 => Zero384Instance,
        64 => Zero512Instance,
        _ => throw new ArgumentException($"Algorithm '{hashAlg.Value}' has no digest width, so it has no Zero Digest.", nameof(hashAlg))
    };

    /// <summary>
    /// Initializes a new digest with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the digest bytes.</param>
    public Tpm2bDigest(IMemoryOwner<byte> storage): base(storage, TpmTags.Digest)
    {
    }

    /// <summary>
    /// Releases the pooled storage, except for a shared <see cref="Zero(TpmiAlgHash)"/> instance: that one owns
    /// no pooled rental and is held simultaneously by every session whose policyDigest is still all zeros, so
    /// one holder's disposal must leave it readable for all the others — the same exemption the base class
    /// already applies to the zero-length <see cref="Empty"/> instance.
    /// </summary>
    /// <param name="disposing">Whether managed state is being released.</param>
    protected override void Dispose(bool disposing)
    {
        if(MemoryOwner is ZeroDigestMemoryOwner)
        {
            return;
        }

        base.Dispose(disposing);
    }

    /// <summary>
    /// Gets the size of the digest data in bytes.
    /// </summary>
    public int Size => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets a value indicating whether this digest is empty.
    /// </summary>
    public bool IsEmpty => Size == 0;

    /// <summary>
    /// Parses a digest from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The declared size is checked against <see cref="TpmReader.Remaining"/> before any pooled buffer is
    /// rented, so a truncated buffer throws the same <see cref="ArgumentOutOfRangeException"/>
    /// <see cref="TpmReader.ReadBytes(int)"/> would have thrown for the same input, but without renting first —
    /// a rent-then-read ordering would otherwise orphan the rental on that throw.
    /// </remarks>
    /// <param name="reader">The reader positioned at the digest.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed digest.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static Tpm2bDigest Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();
        if(size == 0)
        {
            return EmptyInstance;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"Digest size {size} exceeds maximum {MaxSize}.");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), size, $"Digest size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size);

        //Copy digest bytes into owned storage.
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(size);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bDigest(storage);
    }

    /// <summary>
    /// Writes this digest to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Gets the serialized size (2-byte size prefix + data).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Size;

    /// <summary>
    /// Creates a digest from the specified bytes.
    /// </summary>
    /// <param name="bytes">The digest bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created digest.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bDigest Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Digest too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bDigest(storage);
    }

    private string DebuggerDisplay => $"TPM2B_DIGEST({Size} bytes)";

    /// <summary>
    /// Backs a shared <see cref="Zero(TpmiAlgHash)"/> instance: one process-lifetime run of zero octets of a
    /// single digest width, owned by nothing and returned to no pool.
    /// </summary>
    /// <remarks>
    /// A Zero Digest is a constant of the enhanced-authorization formula rather than a per-command value, so it
    /// is held once per width instead of being rented and zero-filled at every session start and every context
    /// reset. Its <see cref="IDisposable.Dispose"/> is a no-op, and <see cref="Tpm2bDigest.Dispose(bool)"/>
    /// recognises this owner so a holder's disposal never marks the shared instance unreadable.
    /// </remarks>
    private sealed class ZeroDigestMemoryOwner: IMemoryOwner<byte>
    {
        /// <summary>The shared run of zero octets this owner exposes.</summary>
        private byte[] Zeros { get; }

        /// <summary>
        /// Initializes the owner over a fresh run of <paramref name="size"/> zero octets.
        /// </summary>
        /// <param name="size">The digest width in octets.</param>
        internal ZeroDigestMemoryOwner(int size)
        {
            Zeros = new byte[size];
        }

        /// <summary>
        /// Gets the zero octets. The value is read-only by contract — a policyDigest is replaced wholesale,
        /// never written through — which is what lets one instance back every holder of that width.
        /// </summary>
        public Memory<byte> Memory => Zeros;

        /// <summary>
        /// Releases nothing: this owner rents from no pool, so it stays valid for every other holder.
        /// </summary>
        public void Dispose()
        {
        }
    }
}
