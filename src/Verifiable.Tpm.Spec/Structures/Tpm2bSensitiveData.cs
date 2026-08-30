using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// TPM2B_SENSITIVE_DATA - a sized buffer for sensitive data in object creation.
/// </summary>
/// <remarks>
/// <para>
/// This structure holds variable-length sensitive data for object creation,
/// prefixed with a 16-bit size field.
/// </para>
/// <para>
/// <b>Wire format (big-endian):</b>
/// </para>
/// <list type="bullet">
///   <item><description>Bytes 0-1: Size (uint16) - number of octets in buffer.</description></item>
///   <item><description>Bytes 2+: Buffer - the sensitive data.</description></item>
/// </list>
/// <para>
/// <b>Usage:</b>
/// </para>
/// <list type="bullet">
///   <item><description>For symmetric keys: the key material.</description></item>
///   <item><description>For sealed data objects: the data to seal.</description></item>
///   <item><description>For asymmetric keys: typically empty (TPM generates the key).</description></item>
///   <item><description>For derived objects: label and context for derivation.</description></item>
/// </list>
/// <para>
/// The buffer is bounded at <see cref="MaxSize"/>: Part 2, clause 11.1.13, Table 169 (TPMU_SENSITIVE_CREATE)
/// states "For interoperability, MAX_SYM_DATA should be 128", and clause 11.1.14, Table 170
/// (TPM2B_SENSITIVE_DATA) bounds <c>buffer[size]</c> at <c>sizeof(TPMU_SENSITIVE_CREATE)</c>. A declared or
/// supplied length wider than that is refused as <c>TPM_RC_SIZE</c>.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.1.13, Table 169; Section 11.1.14, Table 170.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bSensitiveData: SensitiveMemory, ITpmWireType
{
    /// <summary>
    /// The largest sensitive-data buffer a <c>TPM2B_SENSITIVE_DATA</c> may carry: <c>MAX_SYM_DATA</c>, 128
    /// octets (TPM 2.0 Library Part 2, clause 11.1.13, Table 169's "For interoperability, MAX_SYM_DATA should
    /// be 128", mirrored by clause 11.1.14, Table 170's <c>buffer[size]{:sizeof(TPMU_SENSITIVE_CREATE)}</c>
    /// bound). A wider value is not a well-formed <c>TPM2B_SENSITIVE_DATA</c> and is refused with
    /// <c>TPM_RC_SIZE</c>.
    /// </summary>
    public const int MaxSize = 128;

    /// <summary>
    /// Shared empty instance backed by <see cref="EmptyMemoryOwner"/>.
    /// </summary>
    private static Tpm2bSensitiveData EmptyInstance { get; } = new(EmptyMemoryOwner.Instance);

    /// <summary>
    /// Initializes new sensitive data with the specified storage.
    /// </summary>
    /// <param name="storage">The memory owner containing the sensitive bytes.</param>
    public Tpm2bSensitiveData(IMemoryOwner<byte> storage) : base(storage, TpmTags.SensitiveData)
    {
    }

    /// <summary>
    /// Gets the length of the sensitive data in bytes.
    /// </summary>
    public int Length => MemoryOwner.Memory.Length;

    /// <summary>
    /// Gets a value indicating whether this sensitive data is empty.
    /// </summary>
    public bool IsEmpty => Length == 0;

    /// <summary>
    /// Parses sensitive data from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the sensitive data.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed sensitive data.</returns>
    /// <exception cref="InvalidOperationException">The declared size exceeds <see cref="MaxSize"/>, which a TPM answers with <c>TPM_RC_SIZE</c>.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>; checked before any storage is rented, so a truncated frame orphans nothing.</exception>
    public static Tpm2bSensitiveData Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort length = reader.ReadUInt16();

        if(length == 0)
        {
            return EmptyInstance;
        }

        if(length > MaxSize)
        {
            throw new InvalidOperationException($"Sensitive data size {length} exceeds maximum {MaxSize}.");
        }

        if(length > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), (int)length, $"Sensitive data size {length} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> storage = pool.Rent(length, AllocationKind.Pinned);
        ReadOnlySpan<byte> sourceBytes = reader.ReadBytes(length);
        sourceBytes.CopyTo(storage.Memory.Span.Slice(0, length));

        return new Tpm2bSensitiveData(storage);
    }

    /// <summary>
    /// Writes this sensitive data to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteTpm2b(AsReadOnlySpan());
    }

    /// <summary>
    /// Gets the serialized size (2-byte length prefix + data).
    /// </summary>
    public int SerializedSize => sizeof(ushort) + Length;

    /// <summary>
    /// Gets empty sensitive data.
    /// </summary>
    public static Tpm2bSensitiveData Empty => EmptyInstance;

    /// <summary>
    /// Creates sensitive data from the specified bytes.
    /// </summary>
    /// <param name="bytes">The sensitive bytes.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The created sensitive data.</returns>
    /// <exception cref="ArgumentException"><paramref name="bytes"/> is longer than <see cref="MaxSize"/>.</exception>
    public static Tpm2bSensitiveData Create(ReadOnlySpan<byte> bytes, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(bytes.IsEmpty)
        {
            return EmptyInstance;
        }

        if(bytes.Length > MaxSize)
        {
            throw new ArgumentException($"Sensitive data too large. Maximum is {MaxSize} bytes.", nameof(bytes));
        }

        IMemoryOwner<byte> storage = pool.Rent(bytes.Length, AllocationKind.Pinned);
        bytes.CopyTo(storage.Memory.Span);

        return new Tpm2bSensitiveData(storage);
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => $"TPM2B_SENSITIVE_DATA({Length} bytes)";
}
