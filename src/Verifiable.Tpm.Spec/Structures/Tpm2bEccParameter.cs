using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_ECC_PARAMETER - sized buffer for ECC coordinate values.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds a single ECC coordinate (x or y) for elliptic curve points.
/// The maximum size depends on the largest supported curve.
/// </para>
/// <para>
/// <b>Wire format (big-endian):</b>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: size (UINT16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: buffer - the coordinate value (big-endian integer).</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.2.5.1, Table 197.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bEccParameter: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// Maximum size of an ECC parameter (P-521 = 66 bytes).
    /// </summary>
    public const int MaxSize = 66;

    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static Tpm2bEccParameter EmptyInstance { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Gets an empty ECC parameter.
    /// </summary>
    public static Tpm2bEccParameter Empty => EmptyInstance;

    /// <summary>
    /// Initializes a new ECC parameter with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the parameter bytes.</param>
    public Tpm2bEccParameter(IMemoryOwner<byte> storage) : base(storage, TpmTags.EccParameter)
    {
    }

    /// <summary>
    /// Gets the length of the parameter in bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets whether this parameter is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

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
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Parses an ECC parameter from a TPM reader, renting <see cref="AllocationKind.Managed"/> storage — the
    /// shape a public coordinate (an X or Y point member) needs, since it carries no secret.
    /// </summary>
    /// <remarks>
    /// The declared size is checked against <see cref="MaxSize"/> and then <see cref="TpmReader.Remaining"/>
    /// before any pooled buffer is rented, so a truncated or oversized frame throws without ever orphaning a
    /// rental — the same ordering <see cref="Tpm2bDigest.Parse(ref TpmReader, BaseMemoryPool)"/> and
    /// <see cref="Tpm2bPrivate.Parse(ref TpmReader, BaseMemoryPool)"/> use. Delegates to
    /// <see cref="Parse(ref TpmReader, BaseMemoryPool, AllocationKind)"/> with <see cref="AllocationKind.Managed"/>,
    /// the rental a public coordinate takes.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed ECC parameter.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>, or exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static Tpm2bEccParameter Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        return Parse(ref reader, pool, AllocationKind.Managed);
    }

    /// <summary>
    /// Parses an ECC parameter from a TPM reader, renting storage of the caller-chosen
    /// <paramref name="allocationKind"/> — <see cref="AllocationKind.Pinned"/> for the composite's ECC arm
    /// (TPM 2.0 Library Part 2, clause 12.3.2.3, Table 239's <c>ecc</c> member: "the integer private key"),
    /// which must not rest in relocatable memory the runtime could copy without clearing.
    /// </summary>
    /// <remarks>
    /// The declared size is checked against <see cref="MaxSize"/> and then <see cref="TpmReader.Remaining"/>
    /// before any pooled buffer is rented, so a truncated or oversized frame throws without ever orphaning a
    /// rental — the same ordering <see cref="Tpm2bDigest.Parse(ref TpmReader, BaseMemoryPool)"/> and
    /// <see cref="Tpm2bPrivate.Parse(ref TpmReader, BaseMemoryPool)"/> use.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <param name="allocationKind">The rental's allocation kind — pinned for a private scalar, managed for a public coordinate.</param>
    /// <returns>The parsed ECC parameter.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>, or exceeds the octets remaining in <paramref name="reader"/>.</exception>
    public static Tpm2bEccParameter Parse(ref TpmReader reader, BaseMemoryPool pool, AllocationKind allocationKind)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return Empty;
        }

        if(size > MaxSize)
        {
            throw new InvalidOperationException($"ECC parameter size {size} exceeds maximum {MaxSize}.");
        }

        if(size > reader.Remaining)
        {
            throw new InvalidOperationException($"ECC parameter size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(size, allocationKind);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span.Slice(0, size));

        return new Tpm2bEccParameter(storage);
    }

    /// <summary>
    /// Creates an ECC parameter from the specified bytes.
    /// </summary>
    /// <param name="bytes">The parameter bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created ECC parameter.</returns>
    public static Tpm2bEccParameter Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return Empty;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"ECC parameter too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bEccParameter(storage);
    }

    private string DebuggerDisplay => IsEmpty ? "TPM2B_ECC_PARAMETER(empty)" : $"TPM2B_ECC_PARAMETER({Length} bytes)";
}
